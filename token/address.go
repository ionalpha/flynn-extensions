package token

import solana "github.com/gagliardetto/solana-go"

// ParsePubkey parses a base58 Solana public key (a mint address, a payer key), so a caller
// need not import solana-go directly to name one. It returns an error for any string that is
// not a valid Solana public key.
func ParsePubkey(s string) (solana.PublicKey, error) {
	return solana.PublicKeyFromBase58(s)
}
