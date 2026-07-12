package token

import (
	"context"
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"
)

// These tests pin the property that atomicity buys: there is no reachable on-chain state in
// which this engine's mint exists with a LIVE mint authority. The old four-transaction
// lifecycle could produce one (a crash between creating the mint and revoking its authority),
// and needed an abort path to clean it up. A single transaction cannot: Solana applies all of
// its instructions or none of them. So the tests below are about what the engine REPORTS when
// the network misbehaves, because what the chain holds is no longer in question.

// TestMintIsOneTransaction is the whole point. If this ever submits more than once, the mint
// is no longer atomic and the window in which the hot payer can inflate the supply is back.
func TestMintIsOneTransaction(t *testing.T) {
	spec := custodySpec(solana.NewWallet().PublicKey())
	f := &fakeRPC{confirm: true, lastValid: 1000, mintData: revokedMintBytes(scaled(spec.Supply, spec.Decimals), spec.Decimals)}
	e := custodyEngine(f, Devnet)

	if _, _, err := e.Mint(context.Background(), spec); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if f.sendCount != 1 {
		t.Fatalf("the mint took %d transactions, not 1: create/metadata/supply/revoke must land atomically, or the mint authority is live between them", f.sendCount)
	}
}

// TestMintCarriesEveryStep proves the single transaction actually contains the revoke. A
// one-transaction mint that forgot to revoke would pass the test above while leaving an
// infinitely-inflatable token, so the instruction itself is checked.
func TestMintCarriesEveryStep(t *testing.T) {
	spec := custodySpec(solana.NewWallet().PublicKey())
	f := &fakeRPC{confirm: true, lastValid: 1000, mintData: revokedMintBytes(scaled(spec.Supply, spec.Decimals), spec.Decimals)}
	e := custodyEngine(f, Devnet)

	if _, _, err := e.Mint(context.Background(), spec); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if f.lastTx == nil {
		t.Fatal("no transaction was captured")
	}
	if n := len(f.lastTx.Message.Instructions); n != 5 {
		t.Fatalf("the mint transaction carried %d instructions, want 5 (create, ata, mint-to, revoke-freeze, revoke-mint)", n)
	}
	// Both authorities must be revoked IN THIS TRANSACTION. Token Metadata's Create sets a
	// freeze authority, so a mint that only revoked the mint authority would ship the
	// honeypot lever: the issuer could freeze holders so they cannot sell.
	if n := countSetAuthority(f.lastTx); n != 2 {
		t.Fatalf("the mint transaction carries %d SetAuthority instructions, want 2 (freeze AND mint authority revoked)", n)
	}
}

// TestExpiredMintLeavesNothing proves a mint whose blockhash expired is reported as having
// done nothing at all, with no mint address handed back. The transaction can never be
// included, so there is provably no account to reconcile.
func TestExpiredMintLeavesNothing(t *testing.T) {
	// confirm=false with a block height past lastValid: the signature never lands and the
	// blockhash expires.
	f := &fakeRPC{confirm: false, lastValid: 10, blockHeight: 11}
	e := custodyEngine(f, Devnet)

	mint, _, err := e.Mint(context.Background(), custodySpec(solana.NewWallet().PublicKey()))
	if err == nil {
		t.Fatal("an expired mint reported success")
	}
	if !mint.IsZero() {
		t.Fatalf("an expired mint returned address %s: nothing landed, so there is no mint", mint)
	}
	if !strings.Contains(err.Error(), "did not land") {
		t.Fatalf("expired mint error should say nothing landed, got: %v", err)
	}
}

// TestUnconfirmedMintThatLandedIsReportedSafe covers the lost-confirmation case: the
// transaction was submitted, its confirmation never came back, but it DID land. Because the
// transaction is atomic, "it landed" means the finished, revoked, fully-supplied token
// exists. The engine must read the chain and report that, not fail.
func TestUnconfirmedMintThatLandedIsReportedSafe(t *testing.T) {
	spec := custodySpec(solana.NewWallet().PublicKey())
	// The signature never confirms (so send errors), but the account reads back as a
	// finished, revoked mint holding the full supply: it landed after all.
	// failSendAt models a transport failure at the moment the transaction may have reached
	// the node: the signed transaction can still land even though SendTransaction errored, so
	// the outcome is genuinely unknown. The account then reads back as a finished, revoked
	// mint holding the full supply: it landed after all.
	f := &fakeRPC{
		confirm:    true,
		lastValid:  1000,
		failSendAt: 1,
		mintData:   revokedMintBytes(scaled(spec.Supply, spec.Decimals), spec.Decimals),
	}
	e := custodyEngine(f, Devnet)

	mint, _, err := e.Mint(context.Background(), spec)
	if err != nil {
		t.Fatalf("a mint that landed but lost its confirmation was reported as failed: %v", err)
	}
	if mint.IsZero() {
		t.Fatal("no mint address returned for a mint that landed")
	}
}

// TestUnconfirmedMintThatIsUnsafeIsNeverReportedSafe is the paranoid case. If the chain ever
// showed a mint from this engine with a live mint authority, something is deeply wrong (an
// atomic transaction cannot land halfway). The engine must refuse to call it safe rather
// than rationalise it.
func TestUnconfirmedMintThatIsUnsafeIsNeverReportedSafe(t *testing.T) {
	spec := custodySpec(solana.NewWallet().PublicKey())
	// A mint account with a LIVE mint authority (non-zero COption) and the full supply.
	live := revokedMintBytes(scaled(spec.Supply, spec.Decimals), spec.Decimals)
	live[0] = 1 // mint_authority COption::Some
	f := &fakeRPC{confirm: true, lastValid: 1000, failSendAt: 1, mintData: live}
	e := custodyEngine(f, Devnet)

	_, _, err := e.Mint(context.Background(), spec)
	if err == nil {
		t.Fatal("a mint whose authority is STILL LIVE was reported as a success: it can be inflated forever")
	}
	if !strings.Contains(err.Error(), "NOT revoked") && !strings.Contains(err.Error(), "unsafe state") {
		t.Fatalf("expected a refusal naming the live mint authority, got: %v", err)
	}
}

// TestUnreadableMintIsReportedUnresolved proves the engine says "I do not know" when it
// cannot read the chain, rather than claiming success or failure. An unresolved mint is
// still not unsafe, because an atomic transaction cannot have landed halfway.
func TestUnreadableMintIsReportedUnresolved(t *testing.T) {
	// The context is cancelled as the transaction is submitted, so the send never learns its
	// fate: the transaction may or may not have landed. The treasury read (before the send)
	// succeeds; the later MINT read fails, so the engine cannot tell which happened.
	// The signature's status is unreadable and the context then ends, so the send never learns
	// whether the transaction landed. (A submit error alone is not enough: the engine
	// deliberately decides a transaction's fate by watching its signature, not by the submit
	// call, precisely because a transaction that errored on submit can still land.) The
	// treasury read, before the send, succeeds; the later MINT read fails, so the engine
	// genuinely cannot tell what happened.
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeRPC{
		lastValid:    1000,
		sigStatusErr: true, cancel: cancel,
		accountInfoErr: true, accountInfoOKFor: 1,
	}
	e := custodyEngine(f, Devnet)

	_, _, err := e.Mint(ctx, custodySpec(solana.NewWallet().PublicKey()))
	if err == nil {
		t.Fatal("an unreadable mint was reported as a success")
	}
	if !strings.Contains(err.Error(), "unresolved") {
		t.Fatalf("expected an unresolved report, got: %v", err)
	}
}
