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

// The genesis hash of each of Solana's public clusters. A cluster's genesis block is the one
// thing about it that cannot be renamed, proxied, or pointed somewhere else: it is the root
// the chain is built on, and every node on that cluster reports the same value.
const (
	mainnetGenesis = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
	devnetGenesis  = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
	testnetGenesis = "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"
)

// ClassifyGenesis names the network a genesis hash belongs to.
//
// The cluster is read from the chain rather than from the endpoint it was reached through,
// because an endpoint's name is chosen by whoever supplies it and the genesis hash is not. An
// RPC URL with "devnet" in it can serve mainnet, and a classifier that trusted the name would
// hand that operator the whole supply of a real token in a single hot key. Asking the chain
// what chain it is closes that: to be relieved of the treasury requirement, a cluster now has
// to actually be devnet or testnet.
//
// It stays asymmetric. Only a hash we recognise as a test cluster relaxes anything; every
// other value, including the empty string, an unreachable node, and the random genesis of a
// freshly created local validator, comes out Mainnet. The failure modes are not symmetric:
// mistaking mainnet for devnet mints real supply into a hot key, while mistaking devnet for
// mainnet merely demands a treasury address the operator can supply anyway. A local validator
// is a cluster nobody can identify from the outside, so it is named by the caller (OnNetwork),
// never inferred.
func ClassifyGenesis(hash string) Network {
	switch strings.TrimSpace(hash) {
	case devnetGenesis:
		return Devnet
	case testnetGenesis:
		return Testnet
	case mainnetGenesis:
		return Mainnet
	default:
		return Mainnet
	}
}
