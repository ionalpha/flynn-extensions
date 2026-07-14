package signer

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// FuzzSignHandler feeds the signing tool whatever a worker extension might send it. The input
// crosses a trust boundary: it is written by a process this design assumes can be compromised,
// so the handler must survive any bytes at all.
//
// Two things are asserted, and the second is the one that matters. The handler must not panic,
// and it must NEVER return a signature when the policy refused. A panic here is a crash; a
// signature here is a stolen token.
func FuzzSignHandler(f *testing.F) {
	f.Add(`{"payload":"aGVsbG8="}`)
	f.Add(`{"payload":""}`)
	f.Add(`{"payload":"@@@@"}`)
	f.Add(`{}`)
	f.Add(`null`)
	f.Add(`{"payload":123}`)
	f.Add(strings.Repeat("a", 1024))

	key, err := NewEd25519Key(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		f.Fatal(err)
	}
	v := &vault{}
	v.set(key)
	refuse := signTool(v, refusing{rule: "the policy refuses everything"})
	approve := signTool(v, approving{})
	ctx := context.Background()

	f.Fuzz(func(t *testing.T, input string) {
		// A refusing policy must never produce a signature, whatever it is handed.
		out, err := refuse.Handler(ctx, json.RawMessage(input))
		if err == nil {
			t.Fatalf("a refusing policy let something through: input=%q out=%q", input, out)
		}
		if out != "" {
			t.Fatalf("a refusal returned a payload: %q", out)
		}

		// An approving policy may sign, but whatever it returns must be a well-formed reply
		// carrying a signature that actually verifies over the exact bytes requested. It must
		// never return a malformed or empty one and call it success.
		out, err = approve.Handler(ctx, json.RawMessage(input))
		if err != nil {
			return // refused before the key was reached: fine, that is the safe direction
		}
		var reply struct {
			Signature string `json:"signature"`
		}
		if rerr := json.Unmarshal([]byte(out), &reply); rerr != nil {
			t.Fatalf("the signer returned a reply that is not JSON: %q", out)
		}
		sig, serr := base64.StdEncoding.DecodeString(reply.Signature)
		if serr != nil || len(sig) == 0 {
			t.Fatalf("the signer reported success with no usable signature: %q", out)
		}
		var args struct {
			Payload string `json:"payload"`
		}
		if aerr := json.Unmarshal([]byte(input), &args); aerr != nil {
			t.Fatalf("the signer signed an input it could not itself decode: %q", input)
		}
		payload, perr := base64.StdEncoding.DecodeString(args.Payload)
		if perr != nil {
			t.Fatalf("the signer signed a payload that is not base64: %q", input)
		}
		if !ed25519.Verify(key.Public(), payload, sig) {
			t.Fatal("the signer signed something OTHER than the bytes it was asked to sign")
		}
	})
}
