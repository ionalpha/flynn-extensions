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
// The payer key here stands in for flynn core's vault-held signer: the session hands out each
// message and the test signs it with the payer key, exactly as core does over the tool boundary.
package token_test

import (
	"context"
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
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
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
		Name:        "Flynn Localnet",
		Symbol:      "FLN",
		MetadataURI: "https://example.com/fln.json",
		Decimals:    9,
		Supply:      wholeSupply,
	}

	// Drive the resumable session to completion, signing each message with the payer key.
	// This is the exact loop flynn core's process handler runs, minus the sandbox boundary.
	sess := token.StartMint(client, payer.PublicKey(), spec)
	defer sess.Close()

	signs := 0
	var mint solana.PublicKey
	for {
		if out, done := sess.Result(); done {
			if out.Err != nil {
				t.Fatalf("mint failed after %d signatures: %v", signs, out.Err)
			}
			mint = out.Mint
			break
		}
		req, ok := sess.Pending()
		if !ok {
			t.Fatal("session is neither done nor awaiting a signature")
		}
		sig, err := payer.Sign(req.Message)
		if err != nil {
			t.Fatalf("sign request %d: %v", signs, err)
		}
		signs++
		if signs > 8 {
			t.Fatalf("mint requested more than 8 signatures (%d); the choreography should be bounded", signs)
		}
		if err := sess.Advance(token.SignResult{Signature: sig}); err != nil {
			t.Fatalf("advance after signature %d: %v", signs, err)
		}
	}

	t.Logf("minted %s in %d payer signatures", mint, signs)

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
// land, so the mint has rent + fees. On a public cluster this faucet is rate-limited; on a
// local validator it always succeeds, which is why this test runs against a local validator.
func fundPayer(ctx context.Context, t *testing.T, client *rpc.Client, pub solana.PublicKey) {
	t.Helper()
	if _, err := client.RequestAirdrop(ctx, pub, 2*solana.LAMPORTS_PER_SOL, rpc.CommitmentConfirmed); err != nil {
		t.Fatalf("airdrop: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		bal, err := client.GetBalance(ctx, pub, rpc.CommitmentConfirmed)
		if err == nil && bal.Value > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("payer never funded (last err: %v)", err)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context expired waiting for airdrop: %v", ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}
