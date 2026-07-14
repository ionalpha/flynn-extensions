package signer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// refusing is a Policy that refuses everything, naming a rule. It stands in for a real chain
// policy meeting a transaction it will not sign.
type refusing struct{ rule string }

func (r refusing) Approve([]byte) error { return errors.New(r.rule) }

// approving is a Policy that signs anything. It exists only to test the approval path; it is
// what a signer must never actually ship with.
type approving struct{}

func (approving) Approve([]byte) error { return nil }

func testKey(t *testing.T) *Ed25519Key {
	t.Helper()
	k, err := NewEd25519Key(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatalf("NewEd25519Key: %v", err)
	}
	return k
}

// unlocked builds a vault already holding the key, which is the state every signing test cares
// about. The locked state has its own test.
func unlocked(t *testing.T) (*vault, *Ed25519Key) {
	t.Helper()
	key := testKey(t)
	v := &vault{}
	v.set(key)
	return v, key
}

// opener returns an Opener that hands back key for the right passphrase and fails otherwise,
// standing in for a sealed file without touching the disk. It records the path the host named,
// so a test can prove the path travelled.
func opener(key Key, want string) Opener {
	return func(passphrase []byte, _ string) (Key, error) {
		if string(passphrase) != want {
			return nil, errors.New("wrong passphrase")
		}
		return key, nil
	}
}

// pathOpener records the key path it was handed and opens nothing.
func pathOpener(key Key, seen *string) Opener {
	return func(_ []byte, keyPath string) (Key, error) {
		*seen = keyPath
		return key, nil
	}
}

// TestUnlockCarriesTheKeyPathFromTheHost: a released signer is launched from a catalog spec whose
// arguments were fixed before the machine it runs on existed, so it cannot be told where the key
// lives by a flag. The host names the path at unlock, and it has to arrive.
func TestUnlockCarriesTheKeyPathFromTheHost(t *testing.T) {
	var seen string
	tool := unlockTool(&vault{}, pathOpener(testKey(t), &seen), approving{})

	in := json.RawMessage(`{"passphrase":"p","keyPath":"/home/someone/.flynn/solana.sealed"}`)
	if _, err := tool.Handler(context.Background(), in); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if seen != "/home/someone/.flynn/solana.sealed" {
		t.Fatalf("the signer was told the key is at %q, not where the host said", seen)
	}
}

func signRequest(t *testing.T, payload []byte) json.RawMessage {
	t.Helper()
	in, err := json.Marshal(map[string]string{"payload": base64.StdEncoding.EncodeToString(payload)})
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// TestSignToolSignsWhatThePolicyApproves: the happy path produces a signature that actually
// verifies against the advertised public key.
func TestSignToolSignsWhatThePolicyApproves(t *testing.T) {
	v, key := unlocked(t)
	tool := signTool(v, approving{})
	payload := []byte("a transaction the policy is happy with")

	out, err := tool.Handler(context.Background(), signRequest(t, payload))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	var reply struct {
		Signature string `json:"signature"`
	}
	if rerr := json.Unmarshal([]byte(out), &reply); rerr != nil {
		t.Fatalf("decode reply: %v", rerr)
	}
	sig, serr := base64.StdEncoding.DecodeString(reply.Signature)
	if serr != nil {
		t.Fatalf("signature is not base64: %v", serr)
	}
	if !ed25519.Verify(key.Public(), payload, sig) {
		t.Fatal("the signature does not verify against the signer's own public key")
	}
}

// TestRefusalIsAnErrorNotAnEmptySignature is THE property of this package. A refusal must never
// come back as a reply with no signature in it, because a caller could read that as a
// successful signature over nothing. "I refused" must never be readable as "here you go".
func TestRefusalIsAnErrorNotAnEmptySignature(t *testing.T) {
	v, _ := unlocked(t)
	tool := signTool(v, refusing{rule: "mint authority is not revoked in this transaction"})

	out, err := tool.Handler(context.Background(), signRequest(t, []byte("a draining transaction")))
	if err == nil {
		t.Fatal("the policy refused, but the signer returned a result instead of an error")
	}
	if out != "" {
		t.Fatalf("a refusal carried a result payload: %q", out)
	}
	if !strings.Contains(err.Error(), "mint authority is not revoked") {
		t.Fatalf("the refusal did not name the rule that failed: %v", err)
	}
}

// TestSignerRefusesNonsense: an empty, oversized, or malformed payload never reaches the
// policy or the key. The parser is not handed unbounded input from a process that is assumed
// to be compromisable.
func TestSignerRefusesNonsense(t *testing.T) {
	v, _ := unlocked(t)
	tool := signTool(v, approving{})
	ctx := context.Background()

	cases := map[string]json.RawMessage{
		"empty payload":   signRequest(t, nil),
		"not base64":      json.RawMessage(`{"payload":"@@@"}`),
		"absent payload":  json.RawMessage(`{}`),
		"malformed input": json.RawMessage(`not json`),
		"oversized":       signRequest(t, make([]byte, maxPayloadBytes+1)),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := tool.Handler(ctx, in); err == nil {
				t.Fatal("the signer accepted a payload it should have refused outright")
			}
		})
	}
}

// TestPublicToolNeverLeaksThePrivateHalf: the public tool answers with the public key, and the
// reply contains nothing else. A signer that leaked its private half through its own API would
// defeat every other control in the system.
func TestPublicToolNeverLeaksThePrivateHalf(t *testing.T) {
	key := testKey(t)
	tool := unlockTool(&vault{}, opener(key, "pass"), approving{})
	out, err := tool.Handler(context.Background(), json.RawMessage(`{"passphrase":"pass"}`))
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}

	var reply map[string]string
	if rerr := json.Unmarshal([]byte(out), &reply); rerr != nil {
		t.Fatalf("decode: %v", rerr)
	}
	pub, perr := base64.StdEncoding.DecodeString(reply["publicKey"])
	if perr != nil || !ed25519.PublicKey(pub).Equal(ed25519.PublicKey(key.Public())) {
		t.Fatal("the public tool did not return the signer's public key")
	}
	if reply["curve"] != "ed25519" {
		t.Fatalf("curve = %q, want ed25519", reply["curve"])
	}
	// The private half must not appear anywhere in the reply, in any encoding we hand out.
	priv := base64.StdEncoding.EncodeToString(key.priv)
	if strings.Contains(out, priv) || strings.Contains(out, base64.StdEncoding.EncodeToString(key.priv.Seed())) {
		t.Fatal("the public tool's reply contains the PRIVATE key")
	}
}

// TestServeNeedsBothAKeyAndAPolicy: a signer with a key and no policy is a blind signer, and
// must not start at all. This is the one configuration that would quietly undo the design.
func TestServeNeedsBothAKeyAndAPolicy(t *testing.T) {
	ctx := context.Background()
	if err := Serve(ctx, "x", "1", opener(testKey(t), "p"), nil, strings.NewReader(""), &strings.Builder{}); err == nil {
		t.Fatal("a signer with no policy started: it would sign whatever it was handed")
	}
	if err := Serve(ctx, "x", "1", nil, approving{}, strings.NewReader(""), &strings.Builder{}); err == nil {
		t.Fatal("a signer with no key started")
	}
}

// TestALockedSignerSignsNothing: the process starts locked, and stays that way until the host
// unlocks it. A signer that could sign before anyone proved they held the passphrase would make
// the passphrase decorative.
func TestALockedSignerSignsNothing(t *testing.T) {
	tool := signTool(&vault{}, approving{}) // never unlocked
	out, err := tool.Handler(context.Background(), signRequest(t, []byte("anything")))
	if err == nil {
		t.Fatal("a locked signer signed something")
	}
	if out != "" {
		t.Fatalf("a locked signer returned a result: %q", out)
	}
	if !strings.Contains(err.Error(), "locked") {
		t.Fatalf("the refusal did not say the key was locked: %v", err)
	}
}

// TestUnlockRefusesTheWrongPassphrase: a failed unlock leaves the signer locked, so a wrong
// guess does not half-open it.
func TestUnlockRefusesTheWrongPassphrase(t *testing.T) {
	v := &vault{}
	tool := unlockTool(v, opener(testKey(t), "right"), approving{})
	if _, err := tool.Handler(context.Background(), json.RawMessage(`{"passphrase":"wrong"}`)); err == nil {
		t.Fatal("the signer unlocked under the wrong passphrase")
	}
	if v.get() != nil {
		t.Fatal("a FAILED unlock left a key in the vault")
	}
}

// TestUnlockBindsThePolicyToTheKey: a policy whose rules depend on the key (the Solana fee-payer
// rule) is told which key it guards at unlock. Without this the policy would be judging
// transactions against a zero key, and the fee-payer rule would be checking nothing.
func TestUnlockBindsThePolicyToTheKey(t *testing.T) {
	key := testKey(t)
	policy := &bindable{}
	tool := unlockTool(&vault{}, opener(key, "p"), policy)
	if _, err := tool.Handler(context.Background(), json.RawMessage(`{"passphrase":"p"}`)); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if !bytes.Equal(policy.bound, key.Public()) {
		t.Fatal("the policy was not bound to the key it is guarding")
	}
}

// bindable records the key it was bound to.
type bindable struct{ bound []byte }

func (b *bindable) Approve([]byte) error { return nil }
func (b *bindable) BindKey(pub []byte)   { b.bound = pub }
