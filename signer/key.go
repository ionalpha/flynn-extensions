package signer

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
)

// Ed25519Key is a key held in this process's memory, unsealed at startup from an encrypted
// file. It is the software-custody tier: better than a key sitting in plaintext on disk, and
// strictly worse than a key that never leaves a hardware device.
//
// A hardware-backed Key is the tier above and satisfies the same interface: the harness only
// ever asks a Key to sign, never to surrender itself, so swapping the custody does not touch
// the policy or the protocol.
type Ed25519Key struct{ priv ed25519.PrivateKey }

// NewEd25519Key wraps an existing private key.
func NewEd25519Key(priv ed25519.PrivateKey) (*Ed25519Key, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("signer: malformed ed25519 private key")
	}
	return &Ed25519Key{priv: priv}, nil
}

// Public returns the public half. An ed25519 private key is the seed followed by the public
// key, so the public half is read straight out of it rather than through a type assertion that
// can only ever succeed.
func (k *Ed25519Key) Public() []byte {
	return bytes.Clone(k.priv[ed25519.SeedSize:])
}

// Curve names the curve.
func (k *Ed25519Key) Curve() string { return "ed25519" }

// Sign returns a detached ed25519 signature. ed25519 signing is deterministic, so no
// randomness is drawn.
func (k *Ed25519Key) Sign(payload []byte) ([]byte, error) {
	return ed25519.Sign(k.priv, payload), nil
}

var _ Key = (*Ed25519Key)(nil)

// sealedKey is the on-disk form: a passphrase-derived AES-GCM box over the private key. The
// parameters travel with the ciphertext so a file sealed by one build opens in the next.
type sealedKey struct {
	Version int    `json:"version"`
	Curve   string `json:"curve"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	Box     []byte `json:"box"`
}

// Argon2id parameters. Deliberately expensive: the file is the thing an attacker who reads the
// disk walks away with, and the passphrase is the only thing then standing between them and
// the key, so making each guess cost real time and memory is the entire defence.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
	sealVersion  = 1
)

// SealEd25519Key writes priv to path, encrypted under passphrase. It never writes the key in
// the clear, not even briefly: the plaintext exists only in memory.
func SealEd25519Key(path string, priv ed25519.PrivateKey, passphrase []byte) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("signer: malformed ed25519 private key")
	}
	if len(passphrase) == 0 {
		return errors.New("signer: refusing to seal a key under an empty passphrase")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("signer: salt: %w", err)
	}
	gcm, err := boxCipher(passphrase, salt)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, rerr := rand.Read(nonce); rerr != nil {
		return fmt.Errorf("signer: nonce: %w", rerr)
	}
	out, err := json.Marshal(sealedKey{
		Version: sealVersion,
		Curve:   "ed25519",
		Salt:    salt,
		Nonce:   nonce,
		Box:     gcm.Seal(nil, nonce, priv, nil),
	})
	if err != nil {
		return fmt.Errorf("signer: encode sealed key: %w", err)
	}
	return os.WriteFile(path, out, 0o600)
}

// OpenEd25519Key reads a sealed key file and decrypts it. A wrong passphrase, a truncated
// file, or a tampered ciphertext all fail here rather than yielding a key that signs garbage:
// AES-GCM authenticates, so a modified box does not decrypt at all.
func OpenEd25519Key(path string, passphrase []byte) (*Ed25519Key, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the operator names their own key file
	if err != nil {
		return nil, fmt.Errorf("signer: read sealed key: %w", err)
	}
	var sealed sealedKey
	if jerr := json.Unmarshal(raw, &sealed); jerr != nil {
		return nil, errors.New("signer: this is not a sealed key file (a raw key on disk is refused: seal it first)")
	}
	if sealed.Version != sealVersion {
		return nil, fmt.Errorf("signer: sealed key version %d is not supported", sealed.Version)
	}
	if len(passphrase) == 0 {
		return nil, errors.New("signer: no passphrase, so the sealed key cannot be opened")
	}
	gcm, err := boxCipher(passphrase, sealed.Salt)
	if err != nil {
		return nil, err
	}
	if len(sealed.Nonce) != gcm.NonceSize() {
		return nil, errors.New("signer: sealed key is malformed")
	}
	priv, err := gcm.Open(nil, sealed.Nonce, sealed.Box, nil)
	if err != nil {
		// Authentication failed. Do not distinguish a wrong passphrase from a tampered file:
		// the answer to both is the same, and telling them apart only helps someone guessing.
		return nil, errors.New("signer: the sealed key did not open (wrong passphrase, or the file has been altered)")
	}
	return NewEd25519Key(priv)
}

func boxCipher(passphrase, salt []byte) (cipher.AEAD, error) {
	key := argon2.IDKey(passphrase, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("signer: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("signer: gcm: %w", err)
	}
	return gcm, nil
}
