package token

import (
	"context"
	"os"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

// TestE2EMintOnDevnet drives the full guarded mint against devnet: engine.Mint ->
// safety.Guard -> create/metadata/supply/revoke -> on-chain verify. It is skipped
// unless SOLANA_DEVNET_E2E is set and KEYPAIR points at a funded devnet keypair,
// because it spends devnet SOL. The in-process KeySigner here is the devnet test
// path; a deployed mint holds the key in the flynn vault and signs out-of-process.
func TestE2EMintOnDevnet(t *testing.T) {
	if os.Getenv("SOLANA_DEVNET_E2E") == "" {
		t.Skip("set SOLANA_DEVNET_E2E=1 and KEYPAIR=<path> to run the devnet e2e")
	}
	payerKey, err := solana.PrivateKeyFromSolanaKeygenFile(os.Getenv("KEYPAIR"))
	if err != nil {
		t.Fatalf("load keypair: %v", err)
	}
	e := NewEngine(rpc.New(rpc.DevNet_RPC), KeySigner{Key: payerKey})

	spec := MintSpec{Name: "Example Token", Symbol: "EXMP", MetadataURI: "https://example.com/token.json", Decimals: 9, Supply: 1_000_000_000}
	mint, disclosures, err := e.Mint(context.Background(), spec)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	t.Logf("minted %s (disclosures: %d)", mint, len(disclosures))

	st, err := e.Verify(context.Background(), mint)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !st.SupplyFixed() || st.Freezable() {
		t.Fatalf("minted token is not safe: mintAuthorityRevoked=%t freezeAbsent=%t", st.SupplyFixed(), !st.Freezable())
	}
}
