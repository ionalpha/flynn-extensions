package signer

import (
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
	key := testKey(t)
	tool := signTool(key, approving{})
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
	tool := signTool(testKey(t), refusing{rule: "mint authority is not revoked in this transaction"})

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
	tool := signTool(testKey(t), approving{})
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
	out, err := publicTool(key).Handler(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("public: %v", err)
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
	if err := Serve(ctx, "x", "1", testKey(t), nil, strings.NewReader(""), &strings.Builder{}); err == nil {
		t.Fatal("a signer with no policy started: it would sign whatever it was handed")
	}
	if err := Serve(ctx, "x", "1", nil, approving{}, strings.NewReader(""), &strings.Builder{}); err == nil {
		t.Fatal("a signer with no key started")
	}
}
