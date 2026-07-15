package token

import (
	"context"
	"errors"
	"fmt"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/ionalpha/flynn-extensions/token/safety"
)

// MintSpec describes a token to mint. Only safe options are exposed: the scam levers
// (freeze authority, transfer hook, permanent delegate, transfer fee) are not
// configurable here, so the engine cannot produce them, and the safety policy is
// enforced before anything is signed as a second, explicit guard.
type MintSpec struct {
	Name        string
	Symbol      string
	MetadataURI string
	Decimals    uint8
	Supply      uint64 // whole tokens; scaled by decimals when minted

	// Treasury owns the account the whole supply is minted into, and holds the metadata
	// update authority. It is the one address that still has anything after the mint: the
	// mint authority is revoked and no freeze authority is ever set, so the payer ends the
	// lifecycle with no power and no tokens.
	//
	// It is meant to be a multisig vault (a Squads vault is an ordinary pubkey, and an
	// off-curve PDA, which the associated-token account handles). The zero value means the
	// payer keeps the supply, which is fine on a test cluster and is refused on a live one
	// by safety's hot_key_treasury rule.
	Treasury solana.PublicKey
}

// treasury resolves the account that receives the supply: the declared Treasury, or the
// payer when none was declared.
func (e *Engine) treasury(s MintSpec) solana.PublicKey {
	if s.Treasury.IsZero() {
		return e.payer.PublicKey()
	}
	return s.Treasury
}

// checkTreasurySpendable refuses a treasury that could receive the supply but never spend it.
//
// The case that matters is a Squads multisig. It has two addresses: the config account (the
// one the UI shows, owned by the Squads program) and the vault (a signer-only PDA, derived
// from ["multisig", config, "vault", index]). Squads signs as the VAULT. It never signs as
// the config account, so an associated token account owned by the config is a black hole:
// the tokens arrive, and no instruction in any program can ever move them. There is no
// recovery, no key, no threshold. Pasting the wrong one of two very similar addresses would
// destroy the entire supply in a transaction that succeeds.
//
// So: if the treasury is a data account owned by the Squads program, it is the config, and
// this refuses. A vault PDA holds no data and is not owned by Squads, so a correct treasury
// passes. A plain wallet passes. An address that does not exist yet passes, because that is
// what an unfunded vault (and any fresh wallet) looks like.
func (e *Engine) checkTreasurySpendable(ctx context.Context, treasury solana.PublicKey) error {
	info, err := e.rpc.GetAccountInfoWithOpts(ctx, treasury, &rpc.GetAccountInfoOpts{Commitment: rpc.CommitmentFinalized})
	if errors.Is(err, rpc.ErrNotFound) || (err == nil && (info == nil || info.Value == nil)) {
		// The account does not exist yet. That is the NORMAL case for a treasury: a fresh
		// wallet, and a brand-new Squads vault, are both off-chain until something funds
		// them. The RPC reports this either as ErrNotFound or as a null value depending on
		// the client, and both mean the same safe thing. A vault that does not exist yet
		// cannot be a config account, which is the only shape this guard refuses.
		return nil
	}
	if err != nil {
		// A real error (not "absent"): the check could not be performed. Do not mint on an
		// unproven treasury, because the failure this guards against is unrecoverable.
		return fmt.Errorf("treasury %s could not be checked before minting to it: %w", treasury, err)
	}
	if info.Value.Owner.Equals(SquadsV4ProgramID) {
		return fmt.Errorf("treasury %s is a Squads multisig CONFIG account, not its vault: tokens sent here can never be spent by anyone, because Squads only ever signs as the vault. Use the vault address (Squads shows it as the vault/treasury; it is derived from seeds [\"multisig\", %s, \"vault\", index])", treasury, treasury)
	}
	return nil
}

// Mint runs the full guarded lifecycle and returns the mint address plus any
// warn-level disclosures the safety policy attached (a caller must surface these; a
// blocking shape is refused, not returned). It builds the token's final intended
// shape, refuses via the safety policy if that shape is scam-like, then runs create
// -> metadata -> supply -> revoke mint authority, and finally verifies on-chain that
// the result matches the safe shape. A scam-shaped request never reaches signing.
func (e *Engine) Mint(ctx context.Context, s MintSpec) (solana.PublicKey, []safety.Violation, error) {
	// Validate deterministic inputs BEFORE any on-chain action, so an invalid request
	// (a supply that overflows when scaled, or metadata that exceeds the Metaplex
	// limits) is rejected up front and never leaves a partially-created mint with
	// authority still retained.
	if err := validateMetadata(s.Name, s.Symbol, s.MetadataURI); err != nil {
		return solana.PublicKey{}, nil, err
	}
	// A fixed-supply token whose supply is zero is a mint that gets its authority revoked with
	// nothing ever minted: a permanently empty token nobody asked for. It is the shape an omitted
	// or mistyped supply produces (a missing field parses to zero), so it is refused here rather
	// than created on-chain and handed back as a success.
	if s.Supply == 0 {
		return solana.PublicKey{}, nil, errors.New("supply must be greater than zero")
	}
	// Ask the chain which chain it is. This has to happen before the policy runs, because the
	// answer is what decides whether this mint is allowed to put the whole supply in a hot key.
	e.resolveNetwork(ctx)
	if _, err := scaledAmount(s.Supply, s.Decimals); err != nil {
		return solana.PublicKey{}, nil, err
	}

	// The final shape this engine produces: fixed supply (mint authority revoked), no
	// freeze/hook/delegate/fee, no yield or profit claim. The whole supply is minted to the
	// treasury, so the plan records full creator retention; the plan also carries the
	// requested identity so an impersonating name/symbol is refused, and the custody facts
	// so that a live-network mint into the signing hot key is refused before anything is
	// signed.
	treasury := e.treasury(s)
	plan := safety.TokenPlan{
		Chain:               "solana",
		Op:                  "mint",
		CreatorSupplyPct:    100,
		Impersonates:        safety.ImpersonationTarget(s.Name, s.Symbol),
		LiveNetwork:         e.net.Live(),
		TreasuryIsHotSigner: treasury.Equals(e.payer.PublicKey()),
		MutableMetadataURI:  !ContentAddressed(s.MetadataURI),
	}
	if err := safety.Guard(plan); err != nil {
		return solana.PublicKey{}, nil, err
	}
	disclosures := safety.Evaluate(plan) // warn-level only; Guard already refused any blocking shape

	// The treasury has to be an address that can actually spend what it receives. This is
	// checked on-chain, before anything is signed, because the one way to get it wrong is
	// unrecoverable and silent.
	if err := e.checkTreasurySpendable(ctx, treasury); err != nil {
		return solana.PublicKey{}, disclosures, err
	}

	// Bound the whole operation so a caller that passes a deadline-less context cannot hang
	// if the cluster stalls finalization.
	opCtx, cancelOp := context.WithTimeout(ctx, lifecycleBudget)
	defer cancelOp()

	// The mint account is a fresh keypair. Its private key exists only for the length of this
	// call, purely to sign its own creation; it is never persisted and holds no authority
	// afterwards (the mint authority is the payer, and this transaction revokes it).
	mintKey := solana.NewWallet()
	ixs, err := e.buildMint(mintKey.PublicKey(), treasury, s)
	if err != nil {
		return solana.PublicKey{}, disclosures, err
	}

	// ONE transaction: create + metadata + supply + revoke. Solana executes it atomically, so
	// there is no reachable state in which this mint exists with a live mint authority. A
	// failure here means nothing landed, so there is nothing to clean up and nothing unsafe
	// left behind - which is why this path has no abort.
	mint := mintKey.PublicKey()
	if _, err := e.send(opCtx, ixs, rpc.CommitmentFinalized, KeySigner{Key: mintKey.PrivateKey}); err != nil {
		if errors.Is(err, errTxExpired) {
			// The blockhash expired, so the transaction can never be included: provably nothing
			// happened on-chain.
			return solana.PublicKey{}, disclosures, fmt.Errorf("mint did not land: %w", err)
		}
		// The outcome is unknown (a lost confirmation, a dead RPC, a cancelled context). Because
		// the transaction is atomic, the only two possibilities are "nothing happened" and "the
		// finished, safe token exists". Read the chain to find out which, rather than guessing.
		return e.resolveUnconfirmed(ctx, mint, s, disclosures, err)
	}

	// The transaction landed. Verify the finished mint against the chain rather than trusting
	// our own transaction to have done what it said: the on-chain state is the only thing a
	// holder can check, so it is the only thing worth reporting.
	if err := e.verifySafe(opCtx, mint, s); err != nil {
		return mint, disclosures, err
	}
	return mint, disclosures, nil
}

// resolveUnconfirmed decides the outcome of an atomic mint whose confirmation was lost. The
// transaction either landed whole or not at all, so this reads the mint account: if it is
// absent, nothing happened; if it is present, it is the finished token and must still pass
// the same verification as the happy path. Neither branch can leave an inflatable mint,
// which is the whole reason for making the transaction atomic.
func (e *Engine) resolveUnconfirmed(ctx context.Context, mint solana.PublicKey, s MintSpec, disclosures []safety.Violation, cause error) (solana.PublicKey, []safety.Violation, error) {
	checkCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupBudget)
	defer cancel()

	st, err := e.Verify(checkCtx, mint)
	if err != nil {
		// Cannot tell whether it landed. Say so: an unresolved mint is not a failure and not a
		// success, and reporting it as either would be a lie. It is still not unsafe, because
		// an atomic transaction cannot have landed halfway.
		return mint, disclosures, fmt.Errorf("mint %s is unresolved: the transaction was submitted but its outcome could not be read, so it either landed complete or not at all: %w", mint, errors.Join(cause, err))
	}
	if !st.SupplyFixed() || st.Freezable() {
		// Unreachable if the chain is behaving: the same transaction that created this mint
		// revoked its authority. Refuse to call it safe.
		return mint, disclosures, fmt.Errorf("mint %s landed in an unsafe state (supplyFixed=%t freezable=%t), which an atomic mint cannot produce: %w", mint, st.SupplyFixed(), st.Freezable(), cause)
	}
	if err := e.checkSupply(st, mint, s); err != nil {
		return mint, disclosures, err
	}
	return mint, disclosures, nil // it landed after all, and it is safe
}

// verifySafe re-reads a finished mint and proves the safe shape from on-chain state.
func (e *Engine) verifySafe(ctx context.Context, mint solana.PublicKey, s MintSpec) error {
	st, err := e.Verify(ctx, mint)
	if err != nil {
		return fmt.Errorf("post-mint verify of %s failed, so its safety is unproven: %w", mint, err)
	}
	if st.Freezable() {
		return fmt.Errorf("post-mint verify failed: a freeze authority is present on %s", mint)
	}
	if !st.SupplyFixed() {
		return fmt.Errorf("post-mint verify failed: the mint authority is NOT revoked on %s, so the supply could be inflated", mint)
	}
	return e.checkSupply(st, mint, s)
}

// checkSupply proves the mint holds exactly the requested supply.
func (e *Engine) checkSupply(st MintState, mint solana.PublicKey, s MintSpec) error {
	expected, err := scaledAmount(s.Supply, s.Decimals)
	if err != nil {
		return err
	}
	if st.Supply != expected {
		return fmt.Errorf("mint %s is safe (authority revoked, no freeze) but holds supply %d, not the requested %d", mint, st.Supply, expected)
	}
	return nil
}

// Metaplex Token Metadata field byte limits.
const (
	maxNameLen   = 32
	maxSymbolLen = 10
	maxURILen    = 200
)

// validateMetadata rejects identity fields that exceed the Metaplex limits (or an
// empty name/symbol) before any on-chain action, so a too-long field never fails the
// metadata step after the mint already exists.
func validateMetadata(name, symbol, uri string) error {
	switch {
	case len(name) == 0 || len(name) > maxNameLen:
		return fmt.Errorf("name must be 1..%d bytes, got %d", maxNameLen, len(name))
	case len(symbol) == 0 || len(symbol) > maxSymbolLen:
		return fmt.Errorf("symbol must be 1..%d bytes, got %d", maxSymbolLen, len(symbol))
	case len(uri) == 0 || len(uri) > maxURILen:
		return fmt.Errorf("metadataUri must be 1..%d bytes, got %d", maxURILen, len(uri))
	}
	return nil
}
