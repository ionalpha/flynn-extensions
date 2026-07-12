package token

import (
	"net/url"
	"strings"

	solana "github.com/gagliardetto/solana-go"
)

// Network is the cluster an engine runs against. It exists for one reason: to know whether
// the tokens being minted are worth real money, because that is what decides whether the
// whole supply may land in a hot key.
type Network string

// The clusters. Mainnet is the only one whose tokens carry value; the rest are test money.
const (
	Mainnet  Network = "mainnet"
	Devnet   Network = "devnet"
	Testnet  Network = "testnet"
	Localnet Network = "localnet"
)

// ContentAddressed reports whether a metadata URI names its content by hash, so that the
// document it resolves to cannot be changed without changing the URI.
//
// Freezing the metadata account (is_mutable=false) locks the URI string forever, but a URI
// like https://example.com/token.json still resolves to whatever that host serves today. A
// content-addressed URI cannot: the address is the hash. Recognising the two decentralised
// schemes and their common gateways is enough; anything else is reported as mutable, which
// only produces a disclosure, never a refusal.
func ContentAddressed(uri string) bool {
	u := strings.ToLower(strings.TrimSpace(uri))
	if strings.HasPrefix(u, "ipfs://") || strings.HasPrefix(u, "ar://") {
		return true
	}
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" {
		return false
	}
	// Gateway forms: <gw>/ipfs/<cid>, and arweave.net/<txid>.
	if strings.Contains(parsed.Path, "/ipfs/") {
		return true
	}
	return strings.HasSuffix(parsed.Host, "arweave.net")
}

// SquadsV4ProgramID is the Squads v4 multisig program on Solana.
//
// It is here for one check: a Squads multisig has TWO addresses, and only one of them can
// hold tokens. The "multisig" account is the config (threshold, members) and is a data
// account owned by this program. The "vault" is a separate signer-only PDA, derived from
// seeds ["multisig", multisig_address, "vault", vault_index], and it is the vault that
// Squads signs as when it moves assets. Nothing in the program ever signs as the config
// account, so tokens sent to an associated token account owned by the config address can
// never be moved by anyone. Pasting the address shown at the top of the Squads UI - the
// config - instead of the vault would silently destroy the whole supply.
var SquadsV4ProgramID = solana.MustPublicKeyFromBase58("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf")

// Live reports whether this network's tokens are worth real money.
//
// It is defined as "not a known test cluster" rather than "equal to Mainnet" on purpose:
// the zero Network, and any value this package does not recognise, must come out LIVE. A
// caller that forgets to set the network, or sets one we have never heard of, is then held
// to the strict custody rules instead of silently escaping them.
func (n Network) Live() bool {
	switch n {
	case Devnet, Testnet, Localnet:
		return false
	default:
		return true
	}
}

// ClassifyEndpoint names the network an RPC endpoint belongs to.
//
// It is deliberately asymmetric: a host is only called a test cluster when it says so.
// Anything else - a bare IP, a private RPC provider, a proxy, an unparseable string - is
// classified Mainnet, because the failure modes are not symmetric. Mistaking mainnet for
// devnet mints real supply into a hot key; mistaking devnet for mainnet merely demands a
// treasury address that the operator can supply anyway. So the unknown case fails toward
// refusal. This is also why the check does not look for "mainnet" in the host: most real
// mainnet RPCs (Helius, Triton, QuickNode, a self-hosted validator) never contain the word.
func ClassifyEndpoint(endpoint string) Network {
	host := endpoint
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
		host = u.Host
	}
	host = strings.ToLower(host)
	if h, _, ok := strings.Cut(host, ":"); ok {
		host = h
	}

	// Loopback: a local validator. Bare "localhost"/127.0.0.1 with no scheme parses as a
	// path, not a host, so this is checked against the raw string too.
	if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" {
		return Localnet
	}
	// Solana's own clusters name themselves, as do most test-cluster proxies.
	switch {
	case strings.Contains(host, "devnet"):
		return Devnet
	case strings.Contains(host, "testnet"):
		return Testnet
	}
	return Mainnet
}
