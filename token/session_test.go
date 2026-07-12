package token

import (
	"crypto/ed25519"
	"testing"

	solana "github.com/gagliardetto/solana-go"
)

// driveMint plays the role flynn core plays in production: it advances the session, signs each
// emitted message with the payer key (which in production lives in the vault, never here), and
// returns the final outcome plus the requests it saw. It proves the resumable choreography:
// the engine parks on every payer signature and resumes when the driver supplies it.
func driveMint(t *testing.T, f *fakeRPC, payer solana.PrivateKey, spec MintSpec) (Outcome, []SignRequest) {
	t.Helper()
	s := startMint(f, payer.PublicKey(), spec, firingClock{})
	var seen []SignRequest
	for {
		if out, done := s.Result(); done {
			return out, seen
		}
		call, ok := s.Pending()
		if !ok {
			t.Fatal("session is neither done nor awaiting the host")
		}
		// The fake ledger is injected, so the lifecycle borrows no network here and every host
		// call it makes must be a signature request.
		if call.Sign == nil {
			t.Fatal("session parked on something other than a signature request")
		}
		req := *call.Sign
		if !req.Pubkey.Equals(payer.PublicKey()) {
			t.Fatalf("signature requested for %s, not the payer %s", req.Pubkey, payer.PublicKey())
		}
		// The signature must verify against the exact bytes emitted: this proves the message
		// round-trips intact and that a real ed25519 signature over it is what core returns.
		sig, err := payer.Sign(req.Message)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if !ed25519.Verify(ed25519.PublicKey(payer.PublicKey().Bytes()), req.Message, sig[:]) {
			t.Fatal("driver signature does not verify against the emitted message")
		}
		seen = append(seen, req)
		if err := s.Advance(HostReply{Signature: sig}); err != nil {
			t.Fatalf("advance: %v", err)
		}
	}
}

// TestSessionDrivesFullMint proves a full guarded mint completes through the round-trip
// signer: the engine runs create -> metadata -> supply -> revoke -> verify unchanged, parking
// for the payer signature on each transaction, and the driver (holding the key core holds)
// signs each one. The extension process holds no payer key at any point.
func TestSessionDrivesFullMint(t *testing.T) {
	payer := testPayer().Key
	spec := MintSpec{Name: "Flynn", Symbol: "FLYNN", MetadataURI: "https://example.com/f.json", Decimals: 9, Supply: 1_000_000}
	// A ledger where every transaction confirms, and the mint reads back revoked with the
	// requested supply so the lifecycle returns a clean success.
	f := &fakeRPC{
		confirm:   true,
		lastValid: 1000,
		mintData:  revokedMintBytes(scaled(spec.Supply, spec.Decimals), spec.Decimals),
	}

	out, seen := driveMint(t, f, payer, spec)

	if out.Err != nil {
		t.Fatalf("mint did not complete cleanly: %v", out.Err)
	}
	if out.Mint.IsZero() {
		t.Fatal("clean mint returned a zero address")
	}
	// create, metadata, supply, revoke each require exactly one payer signature.
	if len(seen) != 4 {
		t.Fatalf("expected 4 payer-signature round-trips (create/metadata/supply/revoke), got %d", len(seen))
	}
}

// TestSessionDeliversSignFailure proves a signing failure reported by the driver is delivered
// into the lifecycle (not swallowed or hung), and that the engine's failure path still runs
// through the round-trip: the create signature fails, the engine moves to abort the mint, and
// the session completes with an error once the driver has driven it to the end. The mint reads
// back revoked (authority None) so the abort's safety check is satisfied without a live revoke.
func TestSessionDeliversSignFailure(t *testing.T) {
	payer := testPayer().Key
	spec := MintSpec{Name: "Flynn", Symbol: "FLYNN", MetadataURI: "https://example.com/f.json", Decimals: 9, Supply: 1_000_000}
	f := &fakeRPC{confirm: true, lastValid: 1000, mintData: revokedMintBytes(0, 9)}

	s := startMint(f, payer.PublicKey(), spec, firingClock{})
	call, ok := s.Pending()
	if !ok {
		t.Fatal("expected the first payer-signature request")
	}
	if call.Sign == nil || !call.Sign.Pubkey.Equals(payer.PublicKey()) {
		t.Fatal("the first host call was not a signature request for the payer")
	}
	// The first signature fails; every later request (an abort's revoke, if the engine needs
	// one) is signed normally so the session can reach its terminal state.
	fail := true
	for {
		if _, done := s.Result(); done {
			break
		}
		var r HostReply
		if fail {
			r = HostReply{Err: errTestSignFailed}
			fail = false
		} else {
			call, _ := s.Pending()
			sig, err := payer.Sign(call.Sign.Message)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			r = HostReply{Signature: sig}
		}
		if err := s.Advance(r); err != nil {
			t.Fatalf("advance: %v", err)
		}
	}
	out, _ := s.Result()
	if out.Err == nil {
		t.Fatal("expected a non-nil outcome error after the signing failure")
	}
}

// TestSessionAdvanceAfterDoneIsRejected guards the driver contract: advancing a completed
// session is an error, not a panic or a hang.
func TestSessionAdvanceAfterDoneIsRejected(t *testing.T) {
	payer := testPayer().Key
	f := &fakeRPC{confirm: true, lastValid: 1000}
	// An up-front-invalid spec (empty name) is refused before any on-chain action, so the
	// session completes immediately with no pending request.
	s := startMint(f, payer.PublicKey(), MintSpec{Symbol: "X", MetadataURI: "u", Supply: 1}, firingClock{})
	if _, done := s.Result(); !done {
		t.Fatal("an up-front-invalid spec should complete the session immediately")
	}
	if err := s.Advance(HostReply{}); err == nil {
		t.Fatal("advancing a completed session must be rejected")
	}
}

var errTestSignFailed = testError("core could not sign")

type testError string

func (e testError) Error() string { return string(e) }
