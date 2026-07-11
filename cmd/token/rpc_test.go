package main

import (
	"testing"

	"github.com/gagliardetto/solana-go/rpc"
)

// TestResolveEndpoint pins the precedence the token extension uses to pick its RPC endpoint:
// the --rpc flag wins (the only channel that survives the host sandbox, which scrubs the
// environment), then FLYNN_SOLANA_RPC (a bare/dev run), then devnet. Getting this order wrong
// would silently send a mounted extension to the wrong cluster.
func TestResolveEndpoint(t *testing.T) {
	const flagURL = "https://flag.example/rpc"
	const envURL = "https://env.example/rpc"

	cases := []struct {
		name    string
		flagVal string
		envVal  string
		want    string
	}{
		{"flag wins over env", flagURL, envURL, flagURL},
		{"flag wins with no env", flagURL, "", flagURL},
		{"env used when no flag", "", envURL, envURL},
		{"devnet default when neither", "", "", rpc.DevNet_RPC},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveEndpoint(c.flagVal, c.envVal); got != c.want {
				t.Errorf("resolveEndpoint(%q, %q) = %q, want %q", c.flagVal, c.envVal, got, c.want)
			}
		})
	}
}
