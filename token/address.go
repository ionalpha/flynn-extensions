package token

import (
	"encoding/base64"
	"fmt"

	solana "github.com/gagliardetto/solana-go"
)

// ParsePubkey parses a base58 Solana public key (a mint address, a payer key), so a caller
// need not import solana-go directly to name one. It returns an error for any string that is
// not a valid Solana public key.
func ParsePubkey(s string) (solana.PublicKey, error) {
	return solana.PublicKeyFromBase58(s)
}

// ParsePubkeyBytes parses a base64-encoded raw public key. The host-signing handshake carries
// keys as base64 of raw bytes rather than base58, so the host stays free of any chain address
// encoding; this maps that wire form back to a Solana public key.
func ParsePubkeyBytes(b64 string) (solana.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return solana.PublicKey{}, fmt.Errorf("public key is not base64: %w", err)
	}
	if len(raw) != solana.PublicKeyLength {
		return solana.PublicKey{}, fmt.Errorf("public key is %d bytes, want %d", len(raw), solana.PublicKeyLength)
	}
	var pk solana.PublicKey
	copy(pk[:], raw)
	return pk, nil
}

// ParseSignatureBytes parses a base64-encoded raw signature, the wire form the host-signing
// handshake returns, into a Solana signature.
func ParseSignatureBytes(b64 string) (solana.Signature, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return solana.Signature{}, fmt.Errorf("signature is not base64: %w", err)
	}
	var sig solana.Signature
	if len(raw) != len(sig) {
		return solana.Signature{}, fmt.Errorf("signature is %d bytes, want %d", len(raw), len(sig))
	}
	copy(sig[:], raw)
	return sig, nil
}
