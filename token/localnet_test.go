//go:build localnet

// Package token's localnet test drives a full mint against a real Solana validator, proving
// the resumable session builds valid on-chain transactions that a real cluster accepts. The
// deterministic tests in this package run the engine against a fake ledger; this one runs it
// against a live validator so serialization, the Metaplex metadata program interaction, and
// commitment waits are exercised for real.
//
// It is behind the `localnet` build tag so ordinary CI (which has no validator) never runs it.
// Run it against a local validator that has the Metaplex metadata program cloned:
//
//	solana-test-validator --reset --url https://api.devnet.solana.com \
//	  --clone-upgradeable-program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s
//	FLYNN_LOCALNET_RPC=http://127.0.0.1:8899 go test -tags localnet ./token/ -run Localnet -v
//
// The test plays flynn core on BOTH borrowed authorities, exactly as core does over the tool
// boundary. The payer key stands in for core's vault-held signer: the session hands out each
// message and the test signs it. The endpoint stands in for core's HostFetcher: the session
// hands out each JSON-RPC request body and the test POSTs it. The session itself holds neither,
// which is what makes this test possible at all against a LOOPBACK validator: the extension
// never dials anything, so netguard's deny-loopback rule (which applies to an extension's own
// egress) is not in the path. Under flynn, core sends these same bytes through a HostFetcher
// granted the validator's address.
package token_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/ionalpha/flynn-extensions/token"
)

func TestLocalnetMint(t *testing.T) {
	endpoint := os.Getenv("FLYNN_LOCALNET_RPC")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8899"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	client := rpc.New(endpoint)

	// The payer stands in for the core-held vault key: the session never holds it, and the
	// test signs each emitted message with it exactly as flynn core would.
	payer, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatalf("generate payer: %v", err)
	}
	fundPayer(ctx, t, client, payer.PublicKey())

	const wholeSupply = 1_000_000
	spec := token.MintSpec{
		Name:        "Example Localnet",
		Symbol:      "EXLN",
		MetadataURI: "https://example.com/exln.json",
		Decimals:    9,
		Supply:      wholeSupply,
	}

	// Drive the resumable session to completion, servicing every host call it makes: signing each
	// message with the payer key, and sending each JSON-RPC request to the validator. This is the
	// exact loop flynn core's process handler runs, minus the sandbox boundary. The session is
	// given no client and no endpoint, so if any of this leaked back into the extension the mint
	// simply could not proceed.
	sess := token.StartMint(payer.PublicKey(), spec)
	defer sess.Close()

	signs, fetches := 0, 0
	var mint solana.PublicKey
	for {
		if out, done := sess.Result(); done {
			if out.Err != nil {
				t.Fatalf("mint failed after %d signatures and %d fetches: %v", signs, fetches, out.Err)
			}
			mint = out.Mint
			break
		}
		call, ok := sess.Pending()
		if !ok {
			t.Fatal("session is neither done nor awaiting the host")
		}
		var reply token.HostReply
		switch {
		case call.Sign != nil:
			sig, err := payer.Sign(call.Sign.Message)
			if err != nil {
				t.Fatalf("sign request %d: %v", signs, err)
			}
			signs++
			if signs > 8 {
				t.Fatalf("mint requested more than 8 signatures (%d); the choreography should be bounded", signs)
			}
			reply = token.HostReply{Signature: sig}
		case call.Fetch != nil:
			fetches++
			body, err := hostFetch(ctx, endpoint, call.Fetch.Body)
			// A fetch failure is delivered INTO the session (not fatal here) so the engine's own
			// failure path runs, which is what core does too.
			reply = token.HostReply{Body: body, Err: err}
		default:
			t.Fatal("session parked on an empty host call")
		}
		if err := sess.Advance(reply); err != nil {
			t.Fatalf("advance after %d signatures / %d fetches: %v", signs, fetches, err)
		}
	}

	t.Logf("minted %s in %d payer signatures and %d host fetches", mint, signs, fetches)

	// Verify on-chain that the freshly minted token is a safe, fixed-supply SPL mint: both the
	// mint and freeze authorities revoked, decimals as requested, and the whole supply present.
	eng := token.NewEngine(client, nil)
	st, err := eng.Verify(ctx, mint)
	if err != nil {
		t.Fatalf("verify %s: %v", mint, err)
	}
	if !st.SupplyFixed() {
		t.Errorf("mint authority not revoked: supply is not fixed")
	}
	if st.Freezable() {
		t.Errorf("freeze authority present: token can be frozen")
	}
	if st.Decimals != spec.Decimals {
		t.Errorf("decimals = %d, want %d", st.Decimals, spec.Decimals)
	}
	wantScaled := uint64(wholeSupply)
	for i := uint8(0); i < spec.Decimals; i++ {
		wantScaled *= 10
	}
	if st.Supply != wantScaled {
		t.Errorf("supply = %d, want %d (%d whole tokens scaled by %d decimals)", st.Supply, wantScaled, wholeSupply, spec.Decimals)
	}
}

// fundPayer airdrops from the local validator's unlimited faucet and waits for the balance to
// FINALIZE, so the mint has rent + fees. Finalized, not merely confirmed, is the point: the
// engine builds every transaction against the finalized blockhash and its preflight simulation
// runs on the finalized bank, so a confirmed-but-not-finalized airdrop is invisible to the
// first mint transaction and it fails with "no record of a prior credit". On a public cluster
// this faucet is rate-limited; on a local validator it always succeeds, which is why this test
// runs against a local validator.
func fundPayer(ctx context.Context, t *testing.T, client *rpc.Client, pub solana.PublicKey) {
	t.Helper()
	if _, err := client.RequestAirdrop(ctx, pub, 2*solana.LAMPORTS_PER_SOL, rpc.CommitmentFinalized); err != nil {
		t.Fatalf("airdrop: %v", err)
	}
	deadline := time.Now().Add(90 * time.Second)
	for {
		bal, err := client.GetBalance(ctx, pub, rpc.CommitmentFinalized)
		if err == nil && bal.Value > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("payer never funded to finalized (last err: %v)", err)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context expired waiting for airdrop: %v", ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

// hostFetch plays flynn core's HostFetcher: it POSTs the request body the extension handed out to
// the endpoint CORE holds, and returns the response body. The extension never names this address;
// it only ever hands out bytes.
func hostFetch(ctx context.Context, endpoint string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	return io.ReadAll(res.Body)
}
