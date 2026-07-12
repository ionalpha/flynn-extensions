// Package token is an optional, capability-gated Solana token engine: it creates a
// fixed-supply SPL token, attaches immutable Metaplex metadata, mints the supply to a
// treasury, revokes the mint authority, and verifies the result. It is not part of the
// default build; a host mounts it behind the token capability.
//
// There is exactly ONE way to mint with this package: Engine.Mint. The individual steps
// (create, metadata, supply, revoke) are unexported ON PURPOSE. Every one of them is a
// step that, run on its own, can leave an unsafe token behind - a mint whose authority
// was never revoked can be inflated forever - and the safety policy that forbids
// scam-shaped tokens is enforced inside Mint, before anything is signed. Exporting the
// steps would make that policy a convention a caller could skip; keeping them unexported
// makes it a property of the package. If you find yourself needing to export one, you are
// about to create a path to an unsafe token.
//
// The safe shape is not merely checked, it is unbuildable: there is no option anywhere in
// this package to set a freeze authority, a transfer hook, a transfer fee, or a permanent
// delegate. The engine cannot express a scam token, and Mint re-verifies the finished mint
// on-chain rather than trusting its own transactions to have landed.
package token

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	bin "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/ionalpha/flynn-extensions/clock"
)

// mintAccountSize is the byte length of an SPL Mint account.
const mintAccountSize = 82

// Confirmation and cleanup tuning. pollInterval is only the cadence of status polling;
// the DECISION to stop is driven by chain state (a confirmed signature or a passed
// lastValidBlockHeight), never by a fixed number of polls. cleanupBudget is a backstop so
// a dead network cannot hang cleanup forever; reaching it reports the mint as unresolved,
// never as safe. revokeAttempts bounds how many fresh-blockhash revokes cleanup will try.
const (
	pollInterval = 2 * time.Second
	// lifecycleBudget bounds the whole forward mint (create -> metadata -> supply ->
	// finalized revoke) so a caller that passes a deadline-less context cannot hang if the
	// cluster confirms but stalls finalization; on timeout the mint routes to cleanup, which
	// is safe. It is generous so normal finalization under load is never cut short.
	lifecycleBudget = 5 * time.Minute
	cleanupBudget   = 3 * time.Minute
	revokeAttempts  = 5
)

// errTxExpired means a transaction's blockhash passed its last valid block height before
// the signature landed: the transaction can never be included, so it had no on-chain
// effect. It is distinct from an unknown outcome (context ended, RPC unreachable), where
// the transaction may still land and callers must reconcile against on-chain state.
var errTxExpired = errors.New("transaction blockhash expired without landing")

// ErrToken2022Mint marks an account that is a Token-2022 (Token Extensions) mint rather
// than a classic SPL mint. Token-2022 mints can carry transfer hooks, transfer fees, or a
// permanent delegate, so they must be reported as UNSAFE by the verifier, not decoded as a
// plain mint.
var ErrToken2022Mint = errors.New("account is a Token-2022 mint")

// token2022ProgramID owns Token-2022 (Token Extensions) mints.
var token2022ProgramID = solana.MustPublicKeyFromBase58("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")

// metadataProgram is the Metaplex Token Metadata program.
var metadataProgram = solana.MustPublicKeyFromBase58("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s")

// RPCClient is the subset of the Solana RPC the engine uses, named as an interface
// so a test can drive the engine against a fake ledger.
type RPCClient interface {
	GetLatestBlockhash(ctx context.Context, commitment rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error)
	GetBlockHeight(ctx context.Context, commitment rpc.CommitmentType) (uint64, error)
	SendTransactionWithOpts(ctx context.Context, tx *solana.Transaction, opts rpc.TransactionOpts) (solana.Signature, error)
	GetSignatureStatuses(ctx context.Context, searchTransactionHistory bool, sigs ...solana.Signature) (*rpc.GetSignatureStatusesResult, error)
	GetAccountInfoWithOpts(ctx context.Context, account solana.PublicKey, opts *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error)
	GetMinimumBalanceForRentExemption(ctx context.Context, dataSize uint64, commitment rpc.CommitmentType) (uint64, error)
	GetGenesisHash(ctx context.Context) (solana.Hash, error)
}

// Signer authorizes transactions by signing a serialized message. Every method is
// exported, so a caller in another package can supply a vault- or hardware-backed
// signer without touching the engine.
type Signer interface {
	PublicKey() solana.PublicKey
	Sign(message []byte) (solana.Signature, error)
}

// KeySigner is an in-process Signer backed by a private key (devnet/tests). A real
// deployment supplies a hardware- or multisig-backed Signer instead.
type KeySigner struct{ Key solana.PrivateKey }

// PublicKey returns the signer's public key.
func (k KeySigner) PublicKey() solana.PublicKey { return k.Key.PublicKey() }

// Sign signs message with the backing private key.
func (k KeySigner) Sign(message []byte) (solana.Signature, error) { return k.Key.Sign(message) }

// Engine runs token operations against one cluster as one payer/authority.
type Engine struct {
	rpc   RPCClient
	payer Signer
	clk   clock.Timing
	net   Network
	// netPinned records that a caller named the cluster, so the engine must not ask the chain.
	// A local validator cannot be identified from its genesis hash (it is random at creation),
	// so naming it is the only way; everything else is read from the chain.
	netPinned bool
}

// NewEngine builds an engine over an RPC client and a payer/authority signer.
//
// The network defaults to Mainnet, the strictest setting, so an engine built without a
// deliberate WithNetwork is held to real-money custody rules. A caller that forgets to
// say which cluster it is on gets refused, not quietly trusted.
func NewEngine(client RPCClient, payer Signer, opts ...Option) *Engine {
	e := &Engine{rpc: client, payer: payer, clk: clock.System{}, net: Mainnet}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Option configures an Engine at construction.
type Option func(*Engine)

// WithNetwork declares which cluster the engine runs against. It does not change what is
// safe; it changes how much custody rigour is demanded (see safety.TokenPlan.LiveNetwork).
func WithNetwork(n Network) Option {
	return func(e *Engine) { e.net, e.netPinned = n, true }
}

// resolveNetwork establishes which cluster the engine is on by asking the chain for its genesis
// hash. It runs before the safety policy, because the answer is what decides whether the whole
// supply may be minted into the payer's own hot key.
//
// Every outcome that is not a recognised test cluster leaves the engine on Mainnet: a node that
// cannot be reached, a chain that does not know itself, a cluster nobody has heard of. Failing
// to identify the network is not a reason to relax the rules that protect real money, so the
// error is not returned - it simply means the strict path.
func (e *Engine) resolveNetwork(ctx context.Context) {
	if e.netPinned {
		return
	}
	h, err := e.rpc.GetGenesisHash(ctx)
	if err != nil {
		e.net = Mainnet
		return
	}
	e.net = ClassifyGenesis(h.String())
}

// MintState is the observable, verifiable state of a mint.
type MintState struct {
	Mint            solana.PublicKey
	Decimals        uint8
	Supply          uint64
	MintAuthority   *solana.PublicKey // nil means revoked (supply fixed)
	FreezeAuthority *solana.PublicKey // nil means no freeze authority
}

// SupplyFixed reports whether new tokens can never be minted.
func (m MintState) SupplyFixed() bool { return m.MintAuthority == nil }

// Freezable reports whether any account can be frozen.
func (m MintState) Freezable() bool { return m.FreezeAuthority != nil }

// scaledAmount returns whole scaled by 10^decimals, or an error if the result
// overflows uint64. Callers validate this before any on-chain action so an invalid
// supply never leaves a partially-created mint behind.
func scaledAmount(whole uint64, decimals uint8) (uint64, error) {
	amount := whole
	for range decimals {
		if amount > math.MaxUint64/10 {
			return 0, fmt.Errorf("supply %d with %d decimals overflows uint64", whole, decimals)
		}
		amount *= 10
	}
	return amount, nil
}

// Verify fetches and decodes the mint, returning its observable state. It reads at finalized
// commitment so a safety judgment (authority revoked, no freeze) rests on state that can no
// longer be forked out, not on an optimistically confirmed slot.
func (e *Engine) Verify(ctx context.Context, mint solana.PublicKey) (MintState, error) {
	info, err := e.rpc.GetAccountInfoWithOpts(ctx, mint, &rpc.GetAccountInfoOpts{Commitment: rpc.CommitmentFinalized})
	if err != nil {
		return MintState{}, fmt.Errorf("fetch mint: %w", err)
	}
	if info == nil || info.Value == nil {
		return MintState{}, fmt.Errorf("mint %s not found", mint)
	}
	// A Token-2022 mint is owned by a different program and can carry transfer hooks,
	// fees, or a permanent delegate: report it as its own UNSAFE class rather than a bare
	// "wrong owner" error, so a caller is not misled into reading it as "could not check".
	if info.Value.Owner.Equals(token2022ProgramID) {
		return MintState{}, fmt.Errorf("%w: %s (may carry transfer hooks, transfer fees, or a permanent delegate)", ErrToken2022Mint, mint)
	}
	// Guard against decoding a non-mint account as a valid mint, which would otherwise
	// report null authorities as a "safe" token. A mint is owned by the SPL Token
	// program AND is exactly mintAccountSize bytes; a token account (165 bytes) or a
	// multisig is a different, larger layout owned by the same program.
	data := info.Value.Data.GetBinary()
	if !info.Value.Owner.Equals(token.ProgramID) || len(data) != mintAccountSize {
		return MintState{}, fmt.Errorf("account %s is not an SPL mint (wrong owner or size)", mint)
	}
	var m token.Mint
	if err := bin.NewBinDecoder(data).Decode(&m); err != nil {
		return MintState{}, fmt.Errorf("decode mint: %w", err)
	}
	if !m.IsInitialized {
		return MintState{}, fmt.Errorf("account %s is not an initialized SPL mint", mint)
	}
	return MintState{
		Mint: mint, Decimals: m.Decimals, Supply: m.Supply,
		MintAuthority: m.MintAuthority, FreezeAuthority: m.FreezeAuthority,
	}, nil
}

// send builds, signs (with the payer plus any extra signers), submits, and confirms a
// transaction to at least the given commitment, returning its signature. It signs the
// serialized message through the Signer interface, so a hardware- or multisig-backed payer
// works without exposing a private key. Pass rpc.CommitmentFinalized for an irreversible
// step (the mint-authority revoke) whose success is reported to the caller, so a confirmed
// slot that is later forked out can never be mistaken for a permanent result.
func (e *Engine) send(ctx context.Context, ixs []solana.Instruction, commitment rpc.CommitmentType, extra ...Signer) (solana.Signature, error) {
	// Build against a CONFIRMED blockhash (not finalized). Every step reads a fresh
	// blockhash and preflights on the confirmed bank, so each instruction sees the accounts
	// the prior confirmed step created (the mint before its metadata, the ATA before the
	// mint-to). A finalized blockhash would preflight on the finalized bank, which lags our
	// own confirmed writes by ~32 slots: the metadata step would then simulate against a bank
	// where the just-created mint does not yet exist and Metaplex would panic decoding an
	// empty account. The irreversible-step safety guarantee is unaffected: it comes from
	// confirmOrExpire waiting for FINALIZED, not from the blockhash's commitment.
	bh, err := e.rpc.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		return solana.Signature{}, fmt.Errorf("blockhash: %w", err)
	}
	if bh == nil || bh.Value == nil {
		return solana.Signature{}, errors.New("blockhash: empty response")
	}
	tx, err := solana.NewTransaction(ixs, bh.Value.Blockhash, solana.TransactionPayer(e.payer.PublicKey()))
	if err != nil {
		return solana.Signature{}, fmt.Errorf("new tx: %w", err)
	}
	signers := append([]Signer{e.payer}, extra...)
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		return solana.Signature{}, fmt.Errorf("marshal message: %w", err)
	}
	tx.Signatures = make([]solana.Signature, tx.Message.Header.NumRequiredSignatures)
	for i := range tx.Signatures {
		want := tx.Message.AccountKeys[i]
		var s Signer
		for _, cand := range signers {
			if cand.PublicKey().Equals(want) {
				s = cand
				break
			}
		}
		if s == nil {
			return solana.Signature{}, fmt.Errorf("no signer for required account %s", want)
		}
		if tx.Signatures[i], err = s.Sign(msg); err != nil {
			return solana.Signature{}, fmt.Errorf("sign: %w", err)
		}
	}
	// The transaction signature is its fee-payer signature (tx.Signatures[0]), fixed the
	// moment the tx is signed and identical to what the RPC would return. Capture it before
	// submitting so the transaction's fate can be tracked by its signature even if the
	// submit response is lost. A submit error is NOT treated as terminal: a transaction
	// that reached the node can still land, so the outcome is decided by watching the
	// signature until it lands or its blockhash expires, never by the submit call.
	sig := tx.Signatures[0]
	// Preflight on the CONFIRMED bank so simulation sees the accounts our own prior confirmed
	// steps created; the default (finalized) preflight lags those writes and would reject a
	// valid tx (or panic a downstream program) on an account it cannot yet see.
	_, sendErr := e.rpc.SendTransactionWithOpts(ctx, tx, rpc.TransactionOpts{PreflightCommitment: rpc.CommitmentConfirmed})
	switch cerr := e.confirmOrExpire(ctx, sig, bh.Value.LastValidBlockHeight, commitment); {
	case cerr == nil:
		return sig, nil
	case errors.Is(cerr, errTxExpired):
		// Proven never to land, so there was no on-chain effect: report the zero signature
		// (nothing to clean up), folding in any submit error as the cause.
		if sendErr != nil {
			return solana.Signature{}, fmt.Errorf("transaction not submitted and never landed: %w", errors.Join(sendErr, cerr))
		}
		return solana.Signature{}, cerr
	default:
		// Terminal state unknown (context ended) or the transaction landed but failed:
		// return the real signature so the caller can reconcile against on-chain state.
		return sig, cerr
	}
}

// confirmOrExpire waits until a transaction reaches a terminal state and reports which:
// nil once the signature reaches AT LEAST the required commitment; errTxExpired once the
// cluster block height passes lastValidBlockHeight without the signature landing (after
// which it can never land); a failure error if it landed but the transaction failed; or the
// context error if the context ends before the outcome is known (an UNKNOWN outcome, not a
// proof of non-landing). When commitment is rpc.CommitmentFinalized a merely confirmed
// signature is NOT terminal, because a confirmed-but-unfinalized slot can still be forked
// out. Polling cadence uses the clock, but the stop condition is chain state, so no fixed
// timeout can wrongly declare a still-landable transaction dead.
func (e *Engine) confirmOrExpire(ctx context.Context, sig solana.Signature, lastValidBlockHeight uint64, commitment rpc.CommitmentType) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-e.clk.After(pollInterval):
		}
		st, err := e.rpc.GetSignatureStatuses(ctx, true, sig)
		if err != nil || st == nil {
			// The status could not be read, so nothing can be inferred: a transient error
			// is not evidence the transaction is absent. Keep polling; do NOT fall through
			// to the expiry check, or a landed tx would be wrongly declared expired.
			continue
		}
		if len(st.Value) > 0 && st.Value[0] != nil {
			s := st.Value[0]
			if s.Err != nil {
				return fmt.Errorf("tx %s failed on-chain: %v", sig, s.Err)
			}
			switch s.ConfirmationStatus {
			case rpc.ConfirmationStatusFinalized:
				return nil // finalized satisfies every commitment level
			case rpc.ConfirmationStatusConfirmed:
				if commitment != rpc.CommitmentFinalized {
					return nil
				}
			case rpc.ConfirmationStatusProcessed:
				// processed but not yet confirmed or finalized: keep waiting
			}
			continue // seen, but not yet at the required commitment: keep waiting
		}
		// The status read succeeded and the cluster does not know the signature (searched
		// through history). A passed blockhash means it can never land, but a block-height
		// read error leaves the outcome unknown, so keep polling.
		if height, herr := e.rpc.GetBlockHeight(ctx, rpc.CommitmentConfirmed); herr != nil || height <= lastValidBlockHeight {
			continue
		}
		// A single "not found" from one node of a load-balanced RPC is not authoritative
		// (that node may lag the block the tx landed in). Require a second confirmatory
		// "not found" past the valid window before declaring the transaction dead; if the
		// signature reappears or the recheck is unreadable, it is not proven expired.
		st2, err2 := e.rpc.GetSignatureStatuses(ctx, true, sig)
		if err2 == nil && st2 != nil && (len(st2.Value) == 0 || st2.Value[0] == nil) {
			return errTxExpired
		}
	}
}

func metadataPDA(mint solana.PublicKey) (solana.PublicKey, error) {
	pda, _, err := solana.FindProgramAddress(
		[][]byte{[]byte("metadata"), metadataProgram.Bytes(), mint.Bytes()}, metadataProgram,
	)
	return pda, err
}
