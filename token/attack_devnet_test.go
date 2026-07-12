package token_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"
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

	// Each attack is (name, instruction, signer). Every one must be rejected by the cluster.
	attacks := []struct {
		name   string
		ix     solana.Instruction
		signer solana.PrivateKey
	}{
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
	t.Logf("token survived every attack: supply=%d, mint+freeze still revoked", after.Supply)
}

// submit builds, signs, and sends a one-instruction transaction. The cluster runs preflight
// simulation before accepting a transaction, so an invalid instruction (minting with a revoked
// authority, freezing without a freeze authority) is rejected at submit time and returned as an
// error here. A non-nil error means the attack was refused, which is the required outcome.
func submit(ctx context.Context, t *testing.T, client *rpc.Client, ix solana.Instruction, signer solana.PrivateKey) error {
	t.Helper()
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
		tx, err := solana.NewTransaction([]solana.Instruction{ix}, bh.Value.Blockhash, solana.TransactionPayer(signer.PublicKey()))
		if err != nil {
			return err
		}
		if _, err := tx.Sign(func(solana.PublicKey) *solana.PrivateKey { return &signer }); err != nil {
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
