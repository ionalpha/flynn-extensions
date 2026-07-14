package signer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func sealedPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "key.sealed")
}

// mustPub is the public half of a private key: an ed25519 private key is the seed followed by
// the public key.
func mustPub(priv ed25519.PrivateKey) ed25519.PublicKey {
	return ed25519.PublicKey(priv[ed25519.SeedSize:])
}

// TestSealRoundTrips: a key sealed under a passphrase opens again under the same passphrase,
// and signs as itself.
func TestSealRoundTrips(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	path := sealedPath(t)
	pass := []byte("correct horse battery staple")

	if err := SealEd25519Key(path, priv, pass); err != nil {
		t.Fatalf("seal: %v", err)
	}
	key, err := OpenEd25519Key(path, pass)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !ed25519.PublicKey(key.Public()).Equal(mustPub(priv)) {
		t.Fatal("the key that came back is not the key that went in")
	}
	sig, err := key.Sign([]byte("hello"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ed25519.Verify(mustPub(priv), []byte("hello"), sig) {
		t.Fatal("the unsealed key's signature does not verify")
	}
}

// TestSealedFileHoldsNoPlaintextKey is the point of sealing. The bytes on disk must not contain
// the private key, in whole or in part: a sealed file that carries the key is a plaintext key
// with extra steps.
func TestSealedFileHoldsNoPlaintextKey(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	path := sealedPath(t)
	if err := SealEd25519Key(path, priv, []byte("passphrase")); err != nil {
		t.Fatalf("seal: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, priv) {
		t.Fatal("the sealed file contains the private key verbatim")
	}
	if bytes.Contains(raw, priv.Seed()) {
		t.Fatal("the sealed file contains the key's seed, which IS the key")
	}
}

// TestWrongPassphraseFails: the file does not open under the wrong passphrase, and the error
// does not distinguish a wrong passphrase from a tampered file. Telling those apart only helps
// somebody guessing.
func TestWrongPassphraseFails(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	path := sealedPath(t)
	if err := SealEd25519Key(path, priv, []byte("right")); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := OpenEd25519Key(path, []byte("wrong")); err == nil {
		t.Fatal("the sealed key opened under the wrong passphrase")
	}
	if _, err := OpenEd25519Key(path, nil); err == nil {
		t.Fatal("the sealed key opened with no passphrase at all")
	}
}

// TestTamperedBoxDoesNotOpen: AES-GCM authenticates, so a modified ciphertext must fail rather
// than decrypt to a key that signs garbage. A signer that unsealed a corrupted key would
// produce signatures nobody can verify, and it would do so silently.
func TestTamperedBoxDoesNotOpen(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, ed25519.SeedSize))
	path := sealedPath(t)
	pass := []byte("passphrase")
	if err := SealEd25519Key(path, priv, pass); err != nil {
		t.Fatalf("seal: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var sealed sealedKey
	if jerr := json.Unmarshal(raw, &sealed); jerr != nil {
		t.Fatal(jerr)
	}
	sealed.Box[0] ^= 0xff // flip a bit in the ciphertext
	out, err := json.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if werr := os.WriteFile(path, out, 0o600); werr != nil {
		t.Fatal(werr)
	}

	if _, err := OpenEd25519Key(path, pass); err == nil {
		t.Fatal("a tampered sealed key opened anyway")
	}
}

// TestRawKeyOnDiskIsRefused: pointing the signer at an unsealed key file (the JSON byte array
// the chain tooling emits) must fail with an error that says to seal it. Silently accepting a
// plaintext key would make the sealing optional in practice, which is the same as not having it.
func TestRawKeyOnDiskIsRefused(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	nums := make([]int, len(priv))
	for i, b := range priv {
		nums[i] = int(b)
	}
	raw, err := json.Marshal(nums)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "raw.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenEd25519Key(path, []byte("passphrase")); err == nil {
		t.Fatal("the signer opened a RAW key file as if it were sealed")
	}
}

// TestSealRefusesAnEmptyPassphrase: sealing under no passphrase is not sealing.
func TestSealRefusesAnEmptyPassphrase(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	if err := SealEd25519Key(sealedPath(t), priv, nil); err == nil {
		t.Fatal("a key was sealed under an empty passphrase")
	}
}
