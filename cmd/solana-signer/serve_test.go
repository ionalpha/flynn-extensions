package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ionalpha/flynn-extensions/signer"
)

// sealedKeyAt writes a sealed key and returns its path and the key inside it.
func sealedKeyAt(t *testing.T, passphrase string) (string, ed25519.PrivateKey) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, ed25519.SeedSize))
	path := filepath.Join(t.TempDir(), "key.sealed")
	if err := signer.SealEd25519Key(path, priv, []byte(passphrase)); err != nil {
		t.Fatalf("seal: %v", err)
	}
	return path, priv
}

// unlock drives one unlock request through a served signer and returns the reply.
func unlock(t *testing.T, args []string, req string) (string, error) {
	t.Helper()
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"signer_unlock","arguments":` + req + `}}` + "\n")
	var out bytes.Buffer
	err := serveWith(args, in, &out)
	return out.String(), err
}

// TestAReleasedSignerIsToldWhereTheKeyIsAtUnlock is the case that would have shipped broken.
//
// A released signer is launched from a catalog spec, and a spec's arguments are fixed when the
// spec is written: they cannot name a file on a machine nobody has seen yet. So a signer resolved
// from the catalog gets no --key, and if the path could only come from a flag it would start,
// refuse everything, and be useless. The host names the path at unlock instead.
func TestAReleasedSignerIsToldWhereTheKeyIsAtUnlock(t *testing.T) {
	path, priv := sealedKeyAt(t, "hunter2")

	// No --key: exactly how the catalog launches it.
	out, err := unlock(t, nil, `{"passphrase":"hunter2","keyPath":"`+jsonPath(path)+`"}`)
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	if strings.Contains(out, `"isError":true`) {
		t.Fatalf("a signer launched with no --key could not be unlocked by the host: %s", out)
	}
	if !strings.Contains(out, wantPub(t, priv)) {
		t.Fatalf("the unlock did not return the sealed key's public half: %s", out)
	}
}

// TestASignerWithNoKeyAnywhereRefuses: no flag and no path from the host means there is nothing
// to sign with, and it must say so rather than start and fail later at the first transaction.
func TestASignerWithNoKeyAnywhereRefuses(t *testing.T) {
	out, err := unlock(t, nil, `{"passphrase":"hunter2"}`)
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	if !strings.Contains(out, `"isError":true`) {
		t.Fatalf("a signer with no key anywhere unlocked anyway: %s", out)
	}
	if !strings.Contains(out, "no sealed key") {
		t.Fatalf("the refusal does not say the key is missing: %s", out)
	}
}

// TestTheFlagWinsOverTheHostPath: an author running the binary by hand, looking right at the
// path they typed, is not overruled by whatever the host would have named.
func TestTheFlagWinsOverTheHostPath(t *testing.T) {
	path, priv := sealedKeyAt(t, "hunter2")

	out, err := unlock(t, []string{"--key", path},
		`{"passphrase":"hunter2","keyPath":"/nowhere/that/exists.sealed"}`)
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	if strings.Contains(out, `"isError":true`) {
		t.Fatalf("the --key flag was not honoured over the host's path: %s", out)
	}
	if !strings.Contains(out, wantPub(t, priv)) {
		t.Fatalf("the key that opened is not the one --key named: %s", out)
	}
}

// wantPub is the base64 public half the unlock reply should carry.
func wantPub(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	k, err := signer.NewEd25519Key(priv)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k.Public())
}

// jsonPath escapes a filesystem path for embedding in a JSON string (Windows separators).
func jsonPath(p string) string {
	b, _ := json.Marshal(p)
	return strings.Trim(string(b), `"`)
}
