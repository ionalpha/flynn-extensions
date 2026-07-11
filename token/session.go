package token

import (
	"context"
	"errors"

	solana "github.com/gagliardetto/solana-go"

	"github.com/ionalpha/flynn-extensions/clock"
	"github.com/ionalpha/flynn-extensions/token/safety"
)

// This file makes the mint lifecycle resumable across the extension boundary WITHOUT changing
// the reviewed engine. The full synchronous Engine.Mint runs on a goroutine; its payer Signer
// is a roundTripSigner that does not sign locally but hands each message out for the flynn core
// to sign with the vault-held key. The engine's create -> metadata -> supply -> revoke -> verify
// sequence and every failure path (abort, ensureRevoked) run exactly as reviewed; only WHERE
// the payer signature comes from changes. No signing key is ever present in this process.

// SignRequest is one message the mint lifecycle needs signed by the core-held payer key. The
// session emits it and blocks the lifecycle until the driver returns the signature.
type SignRequest struct {
	// Pubkey is the payer/authority public key the signature must come from. Its private key
	// lives in the flynn vault; this process only ever holds the public half.
	Pubkey solana.PublicKey
	// Message is the exact serialized Solana message to sign. Core signs these bytes verbatim
	// with ed25519; it does not parse or interpret them.
	Message []byte
}

// SignResult is the driver's answer to a SignRequest: the signature, or the error core hit
// trying to produce it (delivered into the lifecycle so its failure paths run normally).
type SignResult struct {
	Signature solana.Signature
	Err       error
}

// roundTripSigner is the payer Signer whose PRIVATE key lives in flynn core, never here.
// PublicKey returns the payer's public key, provided by core at session start. Sign does not
// sign locally: it hands the message to the driver and blocks until core returns a result.
type roundTripSigner struct {
	pub   solana.PublicKey
	reqCh chan<- SignRequest
	repCh <-chan SignResult
}

func (s roundTripSigner) PublicKey() solana.PublicKey { return s.pub }

// Sign hands message to the driver and blocks for core's signature. It copies message first:
// the engine may reuse its buffer once Sign returns, and the request crosses to the driver
// goroutine. A context is not threaded here because the Signer interface is key-material-only;
// the session's context bounds the surrounding lifecycle.
func (s roundTripSigner) Sign(message []byte) (solana.Signature, error) {
	msg := append([]byte(nil), message...)
	s.reqCh <- SignRequest{Pubkey: s.pub, Message: msg}
	r := <-s.repCh
	return r.Signature, r.Err
}

var _ Signer = roundTripSigner{}

// Outcome is the final result of a mint session: the mint address and any warn-level safety
// disclosures on success, or a non-nil Err on failure. On a failure that occurred after the
// mint account was created, the engine has already driven it to a supply-fixed (revoked)
// state, so Mint may be non-zero even with Err set.
type Outcome struct {
	Mint        solana.PublicKey
	Disclosures []safety.Violation
	Err         error
}

// Session is a single in-flight mint driven one payer-signature at a time. It is created by
// StartMint, then advanced by the driver (flynn core) until it completes. It is not safe for
// concurrent use by multiple drivers; one driver owns one session.
type Session struct {
	cancel  context.CancelFunc
	reqCh   chan SignRequest
	repCh   chan SignResult
	doneCh  chan Outcome
	pending *SignRequest
	outcome *Outcome
}

// StartMint launches the guarded mint lifecycle for spec on a goroutine and returns the
// session parked at its first action: a payer-signature request, or immediate completion (for
// a spec the engine refuses up front, before any on-chain action). client is the extension's
// own RPC access; payer is the core-held key's PUBLIC half. The private key never enters here.
func StartMint(client RPCClient, payer solana.PublicKey, spec MintSpec) *Session {
	return startMint(client, payer, spec, clock.System{})
}

// startMint is StartMint with an injectable clock so tests drive the engine's confirm/wait
// loops deterministically instead of sleeping. Production always uses the system clock.
func startMint(client RPCClient, payer solana.PublicKey, spec MintSpec, clk clock.Timing) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{
		cancel: cancel,
		reqCh:  make(chan SignRequest),
		repCh:  make(chan SignResult),
		doneCh: make(chan Outcome, 1),
	}
	e := NewEngine(client, roundTripSigner{pub: payer, reqCh: s.reqCh, repCh: s.repCh})
	e.clk = clk
	go func() {
		mint, disc, err := e.Mint(ctx, spec)
		s.doneCh <- Outcome{Mint: mint, Disclosures: disc, Err: err}
	}()
	s.park()
	return s
}

// park blocks until the lifecycle either emits its next signature request or completes, and
// records which. Exactly one fires per park: after emitting a request the lifecycle is blocked
// inside Sign until its reply, so it cannot also complete until the reply is delivered.
func (s *Session) park() {
	select {
	case req := <-s.reqCh:
		s.pending = &req
	case out := <-s.doneCh:
		s.outcome = &out
		s.cancel()
	}
}

// Pending returns the outstanding signature request, if the session is waiting for one.
func (s *Session) Pending() (SignRequest, bool) {
	if s.pending == nil {
		return SignRequest{}, false
	}
	return *s.pending, true
}

// Result returns the final outcome, if the session has completed.
func (s *Session) Result() (Outcome, bool) {
	if s.outcome == nil {
		return Outcome{}, false
	}
	return *s.outcome, true
}

var (
	errSessionDone    = errors.New("token session already completed")
	errSessionAdvance = errors.New("token session: advance without a pending request")
)

// Advance delivers core's result for the outstanding signature request and runs the lifecycle
// until it parks at the next request or completes. Deliver a SignResult with a non-nil Err to
// report that core could not sign; the lifecycle then runs its failure path (revoking any
// created mint) rather than hanging. Advancing a completed session, or one with no pending
// request, is an error.
func (s *Session) Advance(r SignResult) error {
	if s.outcome != nil {
		return errSessionDone
	}
	if s.pending == nil {
		return errSessionAdvance
	}
	s.pending = nil
	s.repCh <- r
	s.park()
	return nil
}

// Close abandons a session, cancelling its lifecycle context so the engine goroutine unwinds
// rather than leaking. It is safe to call after completion. A session abandoned mid-flight may
// leave an unfinished mint on-chain; a driver should prefer to Advance to completion (the
// engine revokes on the way out) and reserve Close for a driver that is itself shutting down.
func (s *Session) Close() { s.cancel() }
