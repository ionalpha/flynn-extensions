package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ionalpha/flynn-extensions/signer"
)

// writeRawKey writes a key in the JSON-byte-array form the chain tooling emits.
func writeRawKey(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
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
	return path
}

// withStdin points os.Stdin at a pipe carrying text, which is what a script, a heredoc, or a CI
// job looks like from in here: not a terminal.
func withStdin(t *testing.T, text string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(text); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()

	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; _ = r.Close() })
}

// TestSealReadsThePassphraseFromAPipe is why this exists. term.ReadPassword needs a terminal,
// and there is not one in a CI job or a provisioning script, so sealing a key could only ever be
// done by hand. It now takes a line from standard input when standard input is not a terminal,
// and the sealed key opens under exactly the passphrase that was piped in.
func TestSealReadsThePassphraseFromAPipe(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	in := writeRawKey(t, priv)
	out := filepath.Join(t.TempDir(), "key.sealed")

	withStdin(t, "correct horse battery staple\n")
	if err := seal([]string{"--in", in, "--out", out}); err != nil {
		t.Fatalf("seal: %v", err)
	}

	// The trailing newline the pipe added is not part of the passphrase: a key sealed under
	// "x\n" would refuse to open under the "x" its owner thinks they chose.
	key, err := signer.OpenEd25519Key(out, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("the sealed key does not open under the passphrase that was piped in: %v", err)
	}
	if !ed25519.PublicKey(key.Public()).Equal(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("the sealed key is not the key that went in")
	}
}

// TestSealRefusesAnEmptyPipedPassphrase: an empty line is not a passphrase, and a key sealed
// under one is a key sealed under nothing.
func TestSealRefusesAnEmptyPipedPassphrase(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	in := writeRawKey(t, priv)
	out := filepath.Join(t.TempDir(), "key.sealed")

	withStdin(t, "\n")
	if err := seal([]string{"--in", in, "--out", out}); err == nil {
		t.Fatal("a key was sealed under an empty passphrase")
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a refused seal still wrote a key file")
	}
}

// TestSealNeedsBothPaths: seal writes a key to disk, so it does not guess where.
func TestSealNeedsBothPaths(t *testing.T) {
	for name, args := range map[string][]string{
		"no arguments": {},
		"no output":    {"--in", "x.json"},
		"no input":     {"--out", "x.sealed"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := seal(args); err == nil {
				t.Fatal("seal ran without being told what to seal, or where")
			}
		})
	}
}
