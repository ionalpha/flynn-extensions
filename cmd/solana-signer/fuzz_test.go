package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

// FuzzReadRawKey feeds the raw-key reader arbitrary file contents. It runs on the operator's
// import path, over a file that may be truncated, corrupted, or simply not a key at all, so it
// must fail cleanly rather than panic or return a malformed key.
//
// A key of the wrong length is the case worth caring about: an ed25519 private key of the wrong
// size panics the standard library at signing time, so it must be rejected here, at the door.
func FuzzReadRawKey(f *testing.F) {
	f.Add([]byte(`[1,2,3]`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`"not an array"`))
	f.Add([]byte(`[300,-1]`))
	f.Add([]byte{})

	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, content []byte) {
		path := filepath.Join(dir, "key.json")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		key, err := readRawKey(path)
		if err != nil {
			return // a bad key file must be an error, and that is the whole requirement
		}
		// If it claimed success, the key must be usable: the wrong length would panic
		// ed25519.Sign, which is exactly the crash this reader exists to prevent.
		if len(key) != ed25519.PrivateKeySize {
			t.Fatalf("readRawKey accepted a %d-byte key", len(key))
		}
		_ = ed25519.Sign(key, []byte("x"))
	})
}
