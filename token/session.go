package token

import (
	"context"
	"errors"

	solana "github.com/gagliardetto/solana-go"

	"github.com/ionalpha/flynn-extensions/clock"
	"github.com/ionalpha/flynn-extensions/token/safety"
)

// This file makes the mint lifecycle resumable across the extension boundary WITHOUT changing
// the reviewed engine. The full synchronous Engine.Mint runs on a goroutine, and BOTH of the
// authorities it would otherwise hold are borrowed from flynn core one round-trip at a time:
//
//	the payer key   its Signer is a roundTripSigner that does not sign locally but hands each
//	                message out for core to sign with the vault-held key.
//	the network     its RPCClient speaks through a hostRPC transport that does not dial
//	                anything but hands each JSON-RPC request body out for core to send.
//
// So this process holds no signing key AND no network. It runs with egress fully denied, which
// is why a compromised extension has nothing to exfiltrate with and nowhere to send it: the
// only bytes that leave are the ones core agreed to send, to the one endpoint core itself
// holds. The engine's create -> metadata -> supply -> revoke -> verify sequence and every
// failure path (abort, ensureRevoked) run exactly as reviewed; only WHERE the signature and
// the network come from changes.

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

// FetchRequest is one JSON-RPC request body the lifecycle needs core to send. It carries no
// destination: core holds the endpoint, so this extension cannot choose where its bytes go.
type FetchRequest struct {
	Body []byte
}

// HostCall is one thing the lifecycle needs the host to do: sign a message, or send a request.
// Exactly one field is set. The driver emits it across the tool boundary and the lifecycle stays
// blocked until the driver answers with a HostReply.
type HostCall struct {
	Sign  *SignRequest
	Fetch *FetchRequest
}

// HostReply is the driver's answer to a HostCall, delivered back into the lifecycle. Signature
// answers a Sign, Body answers a Fetch, and Err answers either: a host that could not sign or
// could not send delivers the error here, so the engine runs its own failure path (revoking a
// mint it already created) rather than hanging.
type HostReply struct {
	Signature solana.Signature
	Body      []byte
	Err       error
}

// roundTripSigner is the payer Signer whose PRIVATE key lives in flynn core, never here.
// PublicKey returns the payer's public key, provided by core at session start. Sign does not
// sign locally: it hands the message to the driver and blocks until core returns a result.
type roundTripSigner struct {
	pub   solana.PublicKey
	reqCh chan<- HostCall
	repCh <-chan HostReply
}

func (s roundTripSigner) PublicKey() solana.PublicKey { return s.pub }

// Sign hands message to the driver and blocks for core's signature. It copies message first:
// the engine may reuse its buffer once Sign returns, and the request crosses to the driver
// goroutine. A context is not threaded here because the Signer interface is key-material-only;
// the session's context bounds the surrounding lifecycle.
func (s roundTripSigner) Sign(message []byte) (solana.Signature, error) {
	msg := append([]byte(nil), message...)
	s.reqCh <- HostCall{Sign: &SignRequest{Pubkey: s.pub, Message: msg}}
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

// VerifyOutcome is the final result of a verify session: the mint's observable state, or the
// error reading it. Verify is read-only and needs no key, but it does need the network, so it is
// a session too: every read it makes crosses back to core to be sent.
type VerifyOutcome struct {
	State MintState
	Err   error
}

// session is one in-flight lifecycle driven one host call at a time: each payer signature and
// each JSON-RPC request it needs is emitted to the driver (flynn core) and answered before the
// lifecycle continues. It is not safe for concurrent use by multiple drivers; one driver owns
// one session. T is the lifecycle's outcome type.
type session[T any] struct {
	cancel  context.CancelFunc
	reqCh   chan HostCall
	repCh   chan HostReply
	doneCh  chan T
	pending *HostCall
	outcome *T
}

// Session is an in-flight mint lifecycle.
type Session = session[Outcome]

// VerifySession is an in-flight read-only verify. It is driven by the same host-call loop as a
// Session, so a driver services both identically.
type VerifySession = session[VerifyOutcome]

// StartVerify launches a read-only verify of mint on a goroutine and returns the session parked
// at its first host call. It holds no key and no network: like a mint, every RPC read it makes
// is handed to core to send.
func StartVerify(mint solana.PublicKey) *VerifySession {
	return startVerify(nil, mint)
}

// startVerify is StartVerify with an injectable RPC client so a test drives it against a fake
// ledger. A nil client means production: the host transport, which has no network of its own.
func startVerify(client RPCClient, mint solana.PublicKey) *VerifySession {
	ctx, cancel := context.WithCancel(context.Background())
	s := newSession[VerifyOutcome](cancel)
	if client == nil {
		client = newHostClient(s.reqCh, s.repCh)
	}
	e := NewEngine(client, nil)
	go func() {
		st, err := e.Verify(ctx, mint)
		s.doneCh <- VerifyOutcome{State: st, Err: err}
	}()
	s.park()
	return s
}

// newSession builds the unstarted channels for a lifecycle. doneCh is buffered so a lifecycle
// that completes after its driver abandoned the session does not leak its goroutine on the send.
func newSession[T any](cancel context.CancelFunc) *session[T] {
	return &session[T]{
		cancel: cancel,
		reqCh:  make(chan HostCall),
		repCh:  make(chan HostReply),
		doneCh: make(chan T, 1),
	}
}

// MintOption configures a mint session.
type MintOption func(*mintConfig)

type mintConfig struct {
	clk clock.Timing
	eng []Option
}

// WithClock sets the timing source the mint's confirmation and cleanup loops poll on. Production
// uses the system clock (the default); a caller that must not sleep in real time, a test above
// this package driving the choreography, supplies its own. It changes only the CADENCE of
// polling: every stop condition is chain state, so no clock can make the engine declare a
// still-landable transaction dead.
func WithClock(clk clock.Timing) MintOption {
	return func(c *mintConfig) {
		if clk != nil {
			c.clk = clk
		}
	}
}

// OnNetwork tells the mint which cluster it is running against, which is what decides whether
// the whole supply may be minted into the payer's own hot key. It is not a default: an engine
// built without it runs as though it were on mainnet, so the custody bar is only ever relaxed
// by a caller that has established the cluster, never by one that forgot to.
func OnNetwork(n Network) MintOption {
	return func(c *mintConfig) { c.eng = append(c.eng, WithNetwork(n)) }
}

// StartMint launches the guarded mint lifecycle for spec on a goroutine and returns the session
// parked at its first action: a host call, or immediate completion (for a spec the engine
// refuses up front, before any on-chain action). payer is the core-held key's PUBLIC half. The
// private key never enters here, and neither does the network: the engine's RPC client is the
// host transport, so every request it makes crosses back to core to be sent.
func StartMint(payer solana.PublicKey, spec MintSpec, opts ...MintOption) *Session {
	cfg := mintConfig{clk: clock.System{}}
	for _, o := range opts {
		o(&cfg)
	}
	return startMint(nil, payer, spec, cfg.clk, cfg.eng...)
}

// startMint is StartMint with an injectable RPC client and clock, so a test drives the engine
// against a fake ledger and through its confirm/wait loops deterministically instead of over a
// real network and real sleeps. A nil client means production: the engine speaks through the
// host transport, which has no network of its own.
func startMint(client RPCClient, payer solana.PublicKey, spec MintSpec, clk clock.Timing, eng ...Option) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	s := newSession[Outcome](cancel)
	if client == nil {
		client = newHostClient(s.reqCh, s.repCh)
	}
	e := NewEngine(client, roundTripSigner{pub: payer, reqCh: s.reqCh, repCh: s.repCh}, eng...)
	e.clk = clk
	go func() {
		mint, disc, err := e.Mint(ctx, spec)
		s.doneCh <- Outcome{Mint: mint, Disclosures: disc, Err: err}
	}()
	s.park()
	return s
}

// park blocks until the lifecycle either emits its next host call or completes, and records
// which. Exactly one fires per park: after emitting a call the lifecycle is blocked waiting for
// its reply, so it cannot also complete until the reply is delivered.
func (s *session[T]) park() {
	select {
	case req := <-s.reqCh:
		s.pending = &req
	case out := <-s.doneCh:
		s.outcome = &out
		s.cancel()
	}
}

// Pending returns the outstanding host call, if the session is waiting on one.
func (s *session[T]) Pending() (HostCall, bool) {
	if s.pending == nil {
		return HostCall{}, false
	}
	return *s.pending, true
}

// Result returns the final outcome, if the session has completed.
func (s *session[T]) Result() (T, bool) {
	var zero T
	if s.outcome == nil {
		return zero, false
	}
	return *s.outcome, true
}

var (
	errSessionDone    = errors.New("token session already completed")
	errSessionAdvance = errors.New("token session: advance without a pending host call")
)

// Advance delivers core's answer to the outstanding host call and runs the lifecycle until it
// parks at the next call or completes. Deliver a HostReply with a non-nil Err to report that
// core could not sign, or could not send; the lifecycle then runs its failure path (revoking any
// created mint) rather than hanging. Advancing a completed session, or one with no pending call,
// is an error.
func (s *session[T]) Advance(r HostReply) error {
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
func (s *session[T]) Close() { s.cancel() }
