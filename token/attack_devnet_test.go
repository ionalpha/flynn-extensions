package token_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	tokenprog "github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/ionalpha/flynn-extensions/token"
)

// TestDevnetMintCannotBeAttacked is the adversarial acceptance test. It mints a real token on
// devnet with the shipping engine, then puts on the attacker's hat and tries, against the live
// chain, to do every bad thing a malicious creator would want to do to a token they minted:
// print more supply, re-arm the mint authority, freeze a holder, and repaint the identity.
//
// The point is not that our code refuses these (our code never issues them). The point is that
// the CHAIN refuses them, because the token was left in a state where they are impossible for
// anyone, including whoever holds the payer key. A safe token is not one whose tooling declines
// to attack it; it is one that cannot be attacked with any tooling. So every attack below is
// built by hand, signed with the payer key that created the mint, and submitted raw. Each MUST
// fail on-chain.
//
// Gated behind SOLANA_DEVNET_E2E + KEYPAIR, like the mint e2e, because it needs a funded key
// and a live cluster.
func TestDevnetMintCannotBeAttacked(t *testing.T) {
	if os.Getenv("SOLANA_DEVNET_E2E") == "" {
		t.Skip("set SOLANA_DEVNET_E2E=1 and KEYPAIR=<path> to run the devnet attack suite")
	}
	payerKey, err := solana.PrivateKeyFromSolanaKeygenFile(os.Getenv("KEYPAIR"))
	if err != nil {
		t.Fatalf("load keypair: %v", err)
	}
	client := rpc.New(rpc.DevNet_RPC)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	// Mint a fresh token to a separate treasury, exactly as a mainnet mint would: the payer
	// (an attacker's key, for the purpose of this test) ends holding no supply and no
	// authority. We keep the treasury's secret so the attacker can even try to act as the
	// holder, which is the strongest position available to them.
	treasury := solana.NewWallet()
	eng := token.NewEngine(client, token.KeySigner{Key: payerKey}, token.WithNetwork(token.Devnet))
	spec := token.MintSpec{
		Name: "Attack Target", Symbol: "ATK",
		MetadataURI: "https://example.com/atk.json", Decimals: 9, Supply: 1_000_000,
		Treasury: treasury.PublicKey(),
	}
	mint, _, err := eng.Mint(ctx, spec)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	t.Logf("minted target %s, treasury %s", mint, treasury.PublicKey())

	// Confirm the starting state from the chain, not from our own report.
	st, err := eng.Verify(ctx, mint)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !st.SupplyFixed() || st.Freezable() {
		t.Fatalf("token did not start in a safe state: supplyFixed=%t freezable=%t", st.SupplyFixed(), st.Freezable())
	}

	payer := payerKey.PublicKey()
	treasuryATA, _, _ := solana.FindAssociatedTokenAddress(treasury.PublicKey(), mint)

	// A stranger: a key with NO relationship to this token at all. A token must be safe not
	// only from the person who made it but from everyone else on the chain, so the same
	// attacks are also tried by this key, which is not the mint authority, not the freeze
	// authority, not the update authority, and holds none of the supply. It is funded (the
	// payer sends it rent) so that "insufficient funds" can never be the reason an attack
	// fails: the attacks must fail because the token forbids them, not because the attacker
	// is broke.
	stranger := solana.NewWallet()
	fundStranger(ctx, t, client, payerKey, stranger.PublicKey())

	// Each attack is (name, instruction, signer). Every one must be rejected by the cluster.
	attacks := []struct {
		name   string
		ix     solana.Instruction
		signer solana.PrivateKey
	}{
		{
			// A stranger tries to print supply. The destination is the treasury's EXISTING
			// account, so the only possible reason this fails is the one under test: the
			// stranger is not the mint authority (nobody is). Targeting a non-existent account
			// would let "account not found" mask the authority check.
			name:   "STRANGER mints supply",
			ix:     tokenprog.NewMintToInstruction(1_000_000_000, mint, treasuryATA, stranger.PublicKey(), nil).Build(),
			signer: stranger.PrivateKey,
		},
		{
			// A stranger tries to claim the mint authority. Setting it requires the current
			// authority (None) to sign, which nobody can do.
			name:   "STRANGER seizes the mint authority",
			ix:     tokenprog.NewSetAuthorityInstruction(tokenprog.AuthorityMintTokens, stranger.PublicKey(), mint, stranger.PublicKey(), nil).Build(),
			signer: stranger.PrivateKey,
		},
		{
			// A stranger tries to freeze the treasury. No freeze authority exists, and they
			// are not it.
			name:   "STRANGER freezes the treasury",
			ix:     tokenprog.NewFreezeAccountInstruction(treasuryATA, mint, stranger.PublicKey(), nil).Build(),
			signer: stranger.PrivateKey,
		},
		{
			// A stranger tries to install a freeze authority they would control.
			name:   "STRANGER installs a freeze authority",
			ix:     tokenprog.NewSetAuthorityInstruction(tokenprog.AuthorityFreezeAccount, stranger.PublicKey(), mint, stranger.PublicKey(), nil).Build(),
			signer: stranger.PrivateKey,
		},
		{
			// Print another billion tokens. The mint authority is None, so MintTo has no
			// valid authority to name; the attacker names themselves and the program rejects it.
			name: "mint more supply with the payer key",
			ix: tokenprog.NewMintToInstruction(
				1_000_000_000_000_000_000, mint, treasuryATA, payer, nil,
			).Build(),
			signer: payerKey,
		},
		{
			// Re-arm the mint authority: set it FROM None back to the payer. Setting an
			// authority requires the CURRENT authority to sign, and the current mint authority
			// is None, so nobody can. This is what "irreversible" means.
			name: "re-establish the mint authority",
			ix: tokenprog.NewSetAuthorityInstruction(
				tokenprog.AuthorityMintTokens, payer, mint, payer, nil,
			).Build(),
			signer: payerKey,
		},
		{
			// Freeze the treasury's account so it cannot sell. There is no freeze authority,
			// so FreezeAccount has no valid authority and is rejected.
			name: "freeze the holder's account",
			ix: tokenprog.NewFreezeAccountInstruction(
				treasuryATA, mint, payer, nil,
			).Build(),
			signer: payerKey,
		},
		{
			// Set a freeze authority now, to freeze holders later. Same story: the freeze
			// authority is None, so it cannot be set by anyone.
			name: "install a freeze authority after the fact",
			ix: tokenprog.NewSetAuthorityInstruction(
				tokenprog.AuthorityFreezeAccount, payer, mint, payer, nil,
			).Build(),
			signer: payerKey,
		},
	}

	for _, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			err := submit(ctx, t, client, a.ix, a.signer)
			if err == nil {
				t.Fatalf("ATTACK SUCCEEDED: %q was accepted by the chain; the token is not safe", a.name)
			}
			msg := err.Error()
			// The attack must be rejected ON ITS MERITS by the SPL Token program, not by a
			// transport or blockhash technicality. A blockhash error means the transaction
			// never reached program execution, so it would "fail" against an UNSAFE token
			// too: that is a false pass, and it is the whole reason this check exists.
			if strings.Contains(msg, "Blockhash not found") || strings.Contains(msg, "BlockhashNotFound") {
				t.Fatalf("INCONCLUSIVE, not a real refusal: %q failed on a blockhash error before the program ran, so this proves nothing about the token: %v", a.name, err)
			}
			// A genuine program rejection surfaces as a custom program error (the SPL Token
			// program's own error code) or an explicit authority/owner complaint.
			if !strings.Contains(msg, "custom program error") &&
				!strings.Contains(strings.ToLower(msg), "authority") &&
				!strings.Contains(strings.ToLower(msg), "owner") &&
				!strings.Contains(msg, "0x4") {
				t.Fatalf("refused, but not clearly by the token program: verify this is a real authority rejection: %v", err)
			}
			t.Logf("rejected by the SPL Token program on its merits: %v", err)
		})
	}

	// Re-verify from the chain after the assault: nothing moved.
	after, err := eng.Verify(ctx, mint)
	if err != nil {
		t.Fatalf("post-attack verify: %v", err)
	}
	if !after.SupplyFixed() || after.Freezable() || after.Supply != st.Supply {
		t.Fatalf("token state changed under attack: %+v -> %+v", st, after)
	}
	t.Logf("token survived every authority attack: supply=%d, mint+freeze still revoked", after.Supply)

	// The identity attack, from the ONE position that could plausibly have power over it: the
	// update authority itself. The metadata update authority is the treasury, and we hold the
	// treasury's key here. If immutability is real, then even this key, the legitimate update
	// authority, cannot repaint the name/symbol/uri into another project's identity after the
	// token is trusted. This is the rug where a token launches as one thing and becomes
	// another; is_mutable=false is supposed to make it impossible for anyone, update authority
	// included.
	//
	// The check is robust to how the Update instruction is built: it does not rely on parsing
	// the rejection, it reads the metadata's name and symbol before and after and asserts they
	// are unchanged. Whether the program rejects the update or (it must not) accepts a no-op,
	// the identity must be byte-identical afterward.
	t.Run("UPDATE AUTHORITY cannot repaint immutable metadata", func(t *testing.T) {
		before := readAssetIdentity(ctx, t, mint)
		// The fee payer is the funded payer key; the update authority is the treasury. Both
		// must sign. buildRepaintAttempt names the payer key as the Update's fee/payer account.
		err := submit(ctx, t, client,
			buildRepaintAttempt(mint, treasury.PublicKey(), payer), payerKey, treasury.PrivateKey)
		// A rejection is the expected outcome; an acceptance is only tolerable if it changed
		// nothing, which the identity check below is what actually decides.
		if err != nil {
			t.Logf("repaint rejected by the program, as required: %v", err)
		}
		afterID := readAssetIdentity(ctx, t, mint)
		if afterID.name != before.name || afterID.symbol != before.symbol || afterID.uri != before.uri {
			t.Fatalf("IMMUTABILITY BROKEN: identity changed from %+v to %+v", before, afterID)
		}
		if afterID.mutable {
			t.Fatalf("metadata reports mutable=true; the identity can be repainted")
		}
		t.Logf("identity is immutable even to its own update authority: %+v", afterID)
	})
}

// fundStranger sends the stranger enough SOL to pay fees, so an attack it makes can never fail
// merely for lack of funds. The transfer is a plain System::Transfer signed by the payer.
func fundStranger(ctx context.Context, t *testing.T, client *rpc.Client, payer solana.PrivateKey, to solana.PublicKey) {
	t.Helper()
	ix := system.NewTransferInstruction(20_000_000, payer.PublicKey(), to).Build()
	if err := submit(ctx, t, client, ix, payer); err != nil {
		// A funded devnet payer should manage this; if the faucet is dry the whole test is
		// moot, so fail loudly rather than run attacks that pass for the wrong reason.
		t.Fatalf("could not fund the stranger, cannot run its attacks honestly: %v", err)
	}
	// Wait for the funds to FINALIZE, not merely confirm: the attack transactions preflight on
	// the finalized bank, so a confirmed-but-not-final credit is invisible to them and the
	// attack would fail on "no record of a prior credit" rather than on the token's merits.
	waitForBalance(ctx, t, client, to)
}

// submit builds, signs, and sends a one-instruction transaction. The cluster runs preflight
// simulation before accepting a transaction, so an invalid instruction (minting with a revoked
// authority, freezing without a freeze authority) is rejected at submit time and returned as an
// error here. A non-nil error means the attack was refused, which is the required outcome.
func submit(ctx context.Context, t *testing.T, client *rpc.Client, ix solana.Instruction, signers ...solana.PrivateKey) error {
	t.Helper()
	if len(signers) == 0 {
		t.Fatal("submit needs at least one signer")
	}
	feePayer := signers[0].PublicKey()
	// A finalized blockhash is used because preflight simulation runs on the finalized bank;
	// a merely-confirmed blockhash is not yet visible there and the node answers "Blockhash
	// not found", which is a transport failure, not a program rejection. The attack must be
	// judged by the program, so the transaction has to actually reach simulation. Retry a few
	// times to ride out the case where even the finalized hash has not propagated to the
	// specific node behind the load balancer yet.
	var lastErr error
	for range 6 {
		bh, err := client.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
		if err != nil {
			lastErr = err
			continue
		}
		tx, err := solana.NewTransaction([]solana.Instruction{ix}, bh.Value.Blockhash, solana.TransactionPayer(feePayer))
		if err != nil {
			return err
		}
		if _, err := tx.Sign(func(k solana.PublicKey) *solana.PrivateKey {
			for i := range signers {
				if signers[i].PublicKey().Equals(k) {
					return &signers[i]
				}
			}
			return nil
		}); err != nil {
			return err
		}
		_, err = client.SendTransaction(ctx, tx)
		if err == nil {
			return nil // the attack was ACCEPTED: the caller treats this as failure
		}
		lastErr = err
		// Only a blockhash-propagation error is worth retrying; a program rejection is the
		// answer we came for, so return it immediately.
		if !strings.Contains(err.Error(), "Blockhash not found") && !strings.Contains(err.Error(), "BlockhashNotFound") {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return lastErr
}

// assetIdentity is the part of a token's identity that immutability must protect.
type assetIdentity struct {
	name    string
	symbol  string
	uri     string
	mutable bool
}

// readAssetIdentity reads the token's on-chain identity through the DAS getAsset method, which
// reflects the Metaplex metadata as the chain holds it. Reading it independently of our own
// engine is the point: the assertion must not trust the code under test.
func readAssetIdentity(ctx context.Context, t *testing.T, mint solana.PublicKey) assetIdentity {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"getAsset","params":{"id":"` + mint.String() + `"}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpc.DevNet_RPC, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("build DAS request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DAS request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Result struct {
			Mutable bool `json:"mutable"`
			Content struct {
				Metadata struct {
					Name   string `json:"name"`
					Symbol string `json:"symbol"`
				} `json:"metadata"`
				JSONURI string `json:"json_uri"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode DAS response: %v", err)
	}
	return assetIdentity{
		name:    out.Result.Content.Metadata.Name,
		symbol:  out.Result.Content.Metadata.Symbol,
		uri:     out.Result.Content.JSONURI,
		mutable: out.Result.Mutable,
	}
}

// buildRepaintAttempt builds a Metaplex Token Metadata Update that tries to rewrite the
// identity to a different project's name and symbol, signed by the update authority. On an
// immutable token the program must refuse it; the test proves the identity is unchanged
// regardless, so this only has to be a plausible Update, not a byte-perfect one.
func buildRepaintAttempt(mint, updateAuthority, payer solana.PublicKey) solana.Instruction {
	metadataProgram := solana.MustPublicKeyFromBase58("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s")
	sysvarInstructions := solana.MustPublicKeyFromBase58("Sysvar1nstructions1111111111111111111111111")
	seed := [][]byte{[]byte("metadata"), metadataProgram.Bytes(), mint.Bytes()}
	metadataPDA, _, _ := solana.FindProgramAddress(seed, metadataProgram)

	// Update (discriminator 50), UpdateArgs::V1, with data = Some(new identity), everything
	// else None. This is the same shape the engine's old update path used.
	buf := &bytes.Buffer{}
	buf.WriteByte(50) // Update
	buf.WriteByte(0)  // UpdateArgs::V1
	buf.WriteByte(0)  // new_update_authority: None
	buf.WriteByte(1)  // data: Some
	writeStr := func(s string) {
		_ = binary.Write(buf, binary.LittleEndian, uint32(len(s)))
		buf.WriteString(s)
	}
	writeStr("Impersonator")                    // the malicious new name
	writeStr("SCAM")                            // the malicious new symbol
	writeStr("https://evil.example.com/x.json") // a hostile new uri
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))
	buf.WriteByte(0) // creators: None
	buf.WriteByte(0) // primary_sale_happened: None
	buf.WriteByte(0) // is_mutable: None
	buf.WriteByte(0) // collection: None
	buf.WriteByte(0) // collection_details: None
	buf.WriteByte(0) // uses: None
	buf.WriteByte(0) // rule_set: None
	buf.WriteByte(0) // authorization_data: None

	// Update accounts: authority(s), delegateRecord(none), token(none), mint, metadata(w),
	// edition(none), payer(s,w), systemProgram, sysvarInstructions, authRulesProgram(none),
	// authRules(none). "none" optional accounts are passed as the program id placeholder.
	accts := solana.AccountMetaSlice{
		solana.Meta(updateAuthority).SIGNER(),
		solana.Meta(metadataProgram), // delegate record: none
		solana.Meta(metadataProgram), // token: none
		solana.Meta(mint),
		solana.Meta(metadataPDA).WRITE(),
		solana.Meta(metadataProgram), // edition: none
		solana.Meta(payer).SIGNER().WRITE(),
		solana.Meta(solana.SystemProgramID),
		solana.Meta(sysvarInstructions),
		solana.Meta(metadataProgram), // auth rules program: none
		solana.Meta(metadataProgram), // auth rules: none
	}
	return solana.NewInstruction(metadataProgram, accts, buf.Bytes())
}

// waitForBalance blocks until the account shows a positive balance, so a funding transfer has
// landed before the funded key is used.
func waitForBalance(ctx context.Context, t *testing.T, client *rpc.Client, pub solana.PublicKey) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		bal, err := client.GetBalance(ctx, pub, rpc.CommitmentFinalized)
		if err == nil && bal.Value > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("account never funded")
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context expired waiting for funding")
		case <-time.After(2 * time.Second):
		}
	}
}
