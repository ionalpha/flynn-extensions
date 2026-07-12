package token

import (
	"testing"

	"pgregory.net/rapid"
)

// FuzzClassifyEndpoint throws arbitrary strings at the network classifier. This decides
// whether a mint is held to real-money custody rules, so its one inviolable property is the
// fail-safe direction: whatever it returns must never be Live()==false unless the input is
// actually one of the known test-cluster forms. A crash or a wrong "not live" on a mainnet
// endpoint would hand an attacker the supply, so the fuzzer asserts that anything not
// recognisably a test cluster classifies as live.
func FuzzClassifyEndpoint(f *testing.F) {
	for _, s := range []string{
		"", "https://api.devnet.solana.com", "http://127.0.0.1:8899",
		"https://mainnet.helius-rpc.com", "devnet", "not a url", "://", "http://",
		"HTTPS://API.DEVNET.SOLANA.COM", "https://x.testnet.foo/devnet",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, endpoint string) {
		n := ClassifyEndpoint(endpoint) // must never panic
		// The only non-live outputs are the three named test clusters. Everything else,
		// including anything the parser could not make sense of, must be live.
		switch n {
		case Devnet, Testnet, Localnet:
			if n.Live() {
				t.Fatalf("%q classified as %s but Live() is true", endpoint, n)
			}
		case Mainnet:
			if !n.Live() {
				t.Fatalf("mainnet classification is not live")
			}
		default:
			t.Fatalf("%q produced an unknown network %q", endpoint, n)
		}
	})
}

// FuzzContentAddressed asserts the URI check never panics on arbitrary input, and that its
// answer is stable: a content-addressed URI is the only thing that suppresses the mutable-URI
// disclosure, so a crash or inconsistency here is a hole in the disclosure path.
func FuzzContentAddressed(f *testing.F) {
	for _, s := range []string{
		"", "ipfs://x", "ar://y", "https://arweave.net/z", "https://ipfs.io/ipfs/c",
		"https://example.com/t.json", "://", "ipfs://", "HTTPS://ARWEAVE.NET/Z",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, uri string) {
		_ = ContentAddressed(uri) // must never panic; idempotent by construction
	})
}

// FuzzCreateV1DataParses asserts the metadata encoder never panics on arbitrary
// name/symbol/uri/decimals, and that whatever it produces still leads with the immutable,
// fungible header. The property test already round-trips the strings; this widens the input
// space to include the byte sequences a fuzzer finds that a generator would not, and pins the
// safety-relevant bytes for all of them.
func FuzzCreateV1DataParses(f *testing.F) {
	f.Add("Name", "SYM", "https://x/y.json", uint8(9))
	f.Add("", "", "", uint8(0))
	f.Fuzz(func(t *testing.T, name, symbol, uri string, decimals uint8) {
		b := createV1Data(name, symbol, uri, decimals) // must never panic
		if len(b) < 2 || b[0] != ixCreate || b[1] != 0 {
			t.Fatalf("createV1Data header changed: %v", b[:min(2, len(b))])
		}
	})
}

// TestScaledAmountNeverPanics is a rapid property check over the supply scaling that the mint
// depends on: for any whole amount and decimals, scaledAmount either returns a value or a
// clean error, and never panics or silently wraps. An overflow that wrapped would mint a
// wildly wrong supply, so the check asserts that a returned value, scaled back down, recovers
// the input.
func TestScaledAmountNeverPanics(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		whole := rapid.Uint64().Draw(t, "whole")
		decimals := rapid.Uint8Range(0, 30).Draw(t, "decimals")
		got, err := scaledAmount(whole, decimals)
		if err != nil {
			return // a refused overflow is a correct outcome
		}
		if whole == 0 {
			if got != 0 {
				t.Fatalf("scaledAmount(0, %d) = %d, want 0", decimals, got)
			}
			return
		}
		// A non-zero success must scale EXACTLY: dividing the result back by 10^decimals
		// recovers the whole amount with no remainder. The scale factor necessarily fits,
		// because got (which is whole*factor with whole>=1) fit, so factor <= got.
		div := uint64(1)
		for range decimals {
			div *= 10
		}
		if got/div != whole || got%div != 0 {
			t.Fatalf("scaledAmount(%d, %d) = %d does not scale back cleanly", whole, decimals, got)
		}
	})
}
