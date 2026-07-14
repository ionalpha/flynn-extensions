package signer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"pgregory.net/rapid"
)

// TestSealedKeyRoundTripsForAnyKeyAndPassphrase: whatever the key and whatever the passphrase,
// sealing then opening returns the same key, and the file on disk never contains it. The
// property has to hold for every passphrase, not just the ones a test author thought of, because
// the passphrase is the only thing between an attacker holding the file and the key inside it.
func TestSealedKeyRoundTripsForAnyKeyAndPassphrase(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		seed := rapid.SliceOfN(rapid.Byte(), ed25519.SeedSize, ed25519.SeedSize).Draw(rt, "seed")
		pass := rapid.SliceOfN(rapid.Byte(), 1, 64).Draw(rt, "passphrase")
		priv := ed25519.NewKeyFromSeed(seed)

		path := filepath.Join(t.TempDir(), "k.sealed")
		if err := SealEd25519Key(path, priv, pass); err != nil {
			rt.Fatalf("seal: %v", err)
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			rt.Fatalf("read: %v", err)
		}
		if bytes.Contains(raw, priv) || bytes.Contains(raw, priv.Seed()) {
			rt.Fatal("the sealed file contains the key it is supposed to be hiding")
		}

		key, err := OpenEd25519Key(path, pass)
		if err != nil {
			rt.Fatalf("open: %v", err)
		}
		if !ed25519.PublicKey(key.Public()).Equal(mustPub(priv)) {
			rt.Fatal("the key that came back is not the key that went in")
		}
	})
}

// TestARefusedPayloadIsNeverSigned: for ANY payload, a policy that refuses means no signature
// comes back. This is the invariant the whole signer exists to hold, so it is asserted over
// arbitrary input rather than over a handful of examples.
func TestARefusedPayloadIsNeverSigned(t *testing.T) {
	key, err := NewEd25519Key(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	v := &vault{}
	v.set(key)
	tool := signTool(v, refusing{rule: "refused"})
	ctx := context.Background()

	rapid.Check(t, func(rt *rapid.T) {
		payload := rapid.SliceOfN(rapid.Byte(), 1, 512).Draw(rt, "payload")
		in, err := json.Marshal(map[string]string{
			"payload": base64.StdEncoding.EncodeToString(payload),
		})
		if err != nil {
			rt.Fatal(err)
		}
		out, err := tool.Handler(ctx, in)
		if err == nil {
			rt.Fatalf("a refused payload was signed: %q", out)
		}
		if out != "" {
			rt.Fatalf("a refusal carried a result: %q", out)
		}
	})
}
