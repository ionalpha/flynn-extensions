package token

import (
	"context"
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/token"
)

// safeSpec is a mint request whose only variable is custody, so each test below isolates the
// custody rule it is about.
// custodyEngine is newTestEngine with an explicit network, and the firing clock so the
// confirm loops do not sleep for real.
func custodyEngine(f *fakeRPC, n Network) *Engine {
	e := NewEngine(f, testPayer(), WithNetwork(n))
	e.clk = firingClock{}
	return e
}

func custodySpec(treasury solana.PublicKey) MintSpec {
	return MintSpec{
		Name: "Example Token", Symbol: "EXMP",
		MetadataURI: "ipfs://bafyexamplecid", Decimals: 9, Supply: 1_000_000,
		Treasury: treasury,
	}
}

// TestLiveMintIntoHotSignerIsRefused is the rule that exists to stop a mainnet mint dropping
// the entire supply into the one key an agent holds online. It must be refused BEFORE any
// transaction is signed, so the mint never reaches the chain at all.
func TestLiveMintIntoHotSignerIsRefused(t *testing.T) {
	f := &fakeRPC{confirm: true, lastValid: 1000}
	e := custodyEngine(f, Mainnet)

	// No treasury: the supply would land in the payer's own account.
	_, _, err := e.Mint(context.Background(), custodySpec(solana.PublicKey{}))
	if err == nil {
		t.Fatal("a mainnet mint with no treasury was allowed: the whole supply would sit in the hot signing key")
	}
	if !strings.Contains(err.Error(), "hot_key_treasury") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	if f.sendCount != 0 {
		t.Fatalf("the refusal came too late: %d transactions were already submitted", f.sendCount)
	}
}

// TestLiveMintIntoTreasuryIsAllowed proves the rule is about custody, not about mainnet: the
// same live network with a real treasury is permitted.
func TestLiveMintIntoTreasuryIsAllowed(t *testing.T) {
	vault := solana.NewWallet().PublicKey()
	f := &fakeRPC{confirm: true, lastValid: 1000, mintData: revokedMintBytes(scaled(1_000_000, 9), 9)}
	e := custodyEngine(f, Mainnet)

	if _, _, err := e.Mint(context.Background(), custodySpec(vault)); err != nil {
		t.Fatalf("a mainnet mint into a separate treasury was refused: %v", err)
	}
}

// TestTestnetMintIntoHotSignerIsAllowed proves the custody bar is raised by real value, not
// applied blindly: on a test cluster the payer may keep the supply, which is what every
// devnet run and every test does.
func TestTestnetMintIntoHotSignerIsAllowed(t *testing.T) {
	f := &fakeRPC{confirm: true, lastValid: 1000, mintData: revokedMintBytes(scaled(1_000_000, 9), 9)}
	e := custodyEngine(f, Devnet)

	if _, _, err := e.Mint(context.Background(), custodySpec(solana.PublicKey{})); err != nil {
		t.Fatalf("a devnet mint into the payer was refused: %v", err)
	}
}

// TestUnknownNetworkIsTreatedAsLive is the fail-safe. The zero Network, and any endpoint we
// do not recognise, must be held to real-money rules. A misconfiguration has to fail toward
// refusing, never toward minting real supply into a hot key.
func TestUnknownNetworkIsTreatedAsLive(t *testing.T) {
	if !Network("").Live() {
		t.Fatal("the zero Network reported itself as not live: an unset network would escape the custody rules")
	}
	if !Network("some-new-cluster").Live() {
		t.Fatal("an unrecognised Network reported itself as not live")
	}
	for _, n := range []Network{Devnet, Testnet, Localnet} {
		if n.Live() {
			t.Fatalf("%s reported itself as a live-value network", n)
		}
	}
}

// TestClassifyEndpointFailsSafe proves the endpoint classifier is asymmetric on purpose: only
// a host that identifies itself as a test cluster is treated as one. A private mainnet RPC
// (Helius, Triton, a bare IP) does not contain the word "mainnet", so a classifier that
// looked for it would hand an attacker the whole supply.
func TestClassifyEndpointFailsSafe(t *testing.T) {
	live := []string{
		"https://mainnet.helius-rpc.com/?api-key=x", // a real mainnet RPC
		"https://example-rpc.provider.io",           // says nothing about itself
		"http://10.0.0.7:8899",                      // a bare private IP
		"",                                          // nothing at all
		"::::not a url::::",                         // unparseable
	}
	for _, e := range live {
		if got := ClassifyEndpoint(e); !got.Live() {
			t.Errorf("ClassifyEndpoint(%q) = %s, which is not live: an unrecognised endpoint must be treated as real money", e, got)
		}
	}
	tests := map[string]Network{
		"https://api.devnet.solana.com":  Devnet,
		"https://api.testnet.solana.com": Testnet,
		"http://127.0.0.1:8899":          Localnet,
		"http://localhost:8899":          Localnet,
	}
	for endpoint, want := range tests {
		if got := ClassifyEndpoint(endpoint); got != want {
			t.Errorf("ClassifyEndpoint(%q) = %s, want %s", endpoint, got, want)
		}
	}
}

// TestSquadsConfigAccountAsTreasuryIsRefused guards the one mistake that silently destroys
// the supply. A Squads multisig has two addresses; only the vault can spend. Tokens sent to
// an account owned by the Squads program (the config) can never be moved by anyone, and the
// transaction that sends them SUCCEEDS. So it must be caught before signing.
func TestSquadsConfigAccountAsTreasuryIsRefused(t *testing.T) {
	squadsConfig := solana.NewWallet().PublicKey()
	f := &fakeRPC{confirm: true, lastValid: 1000, accountOwner: SquadsV4ProgramID}
	e := custodyEngine(f, Mainnet)

	_, _, err := e.Mint(context.Background(), custodySpec(squadsConfig))
	if err == nil {
		t.Fatal("minting the whole supply into a Squads CONFIG account was allowed: the tokens would be unspendable forever")
	}
	if !strings.Contains(err.Error(), "CONFIG account") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	if f.sendCount != 0 {
		t.Fatalf("the refusal came too late: %d transactions were already submitted", f.sendCount)
	}
}

// TestOrdinaryTreasuryPassesTheSpendableCheck proves the Squads guard does not reject the
// normal cases: a plain wallet (owned by the system program) and a vault PDA, which holds no
// data and is not owned by Squads.
func TestOrdinaryTreasuryPassesTheSpendableCheck(t *testing.T) {
	for name, owner := range map[string]solana.PublicKey{
		"a funded wallet or vault PDA": solana.SystemProgramID,
		"a token account":              token.ProgramID,
	} {
		f := &fakeRPC{
			confirm: true, lastValid: 1000, accountOwner: owner,
			mintData: revokedMintBytes(scaled(1_000_000, 9), 9),
		}
		e := custodyEngine(f, Mainnet)
		if _, _, err := e.Mint(context.Background(), custodySpec(solana.NewWallet().PublicKey())); err != nil {
			t.Errorf("%s was refused as a treasury: %v", name, err)
		}
	}
}

// TestMutableMetadataURIIsDisclosedOnLiveNetworks proves the off-chain half of immutability is
// surfaced. Freezing the metadata locks the URI string, not the JSON it points at: a logo and
// name served from a web host can still be swapped after launch. That is a disclosure, not a
// refusal, because hosting on your own domain is a legitimate choice.
func TestMutableMetadataURIIsDisclosedOnLiveNetworks(t *testing.T) {
	vault := solana.NewWallet().PublicKey()
	spec := custodySpec(vault)
	spec.MetadataURI = "https://example.com/token.json" // not content-addressed
	f := &fakeRPC{confirm: true, lastValid: 1000, mintData: revokedMintBytes(scaled(1_000_000, 9), 9)}
	e := custodyEngine(f, Mainnet)

	_, disclosures, err := e.Mint(context.Background(), spec)
	if err != nil {
		t.Fatalf("a web-hosted metadata URI must be disclosed, not refused: %v", err)
	}
	var found bool
	for _, d := range disclosures {
		if d.Code == "mutable_metadata_uri" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no mutable_metadata_uri disclosure for a web-hosted URI; got %v", disclosures)
	}
}

// TestContentAddressedURIs pins which URIs count as provably fixed.
func TestContentAddressedURIs(t *testing.T) {
	fixed := []string{
		"ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		"ar://Iaq_kMBIQfF7EBQyCJZAqBIz1lJ1uPmTLYwUUyG_ATE",
		"https://ipfs.io/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		"https://arweave.net/Iaq_kMBIQfF7EBQyCJZAqBIz1lJ1uPmTLYwUUyG_ATE",
	}
	for _, u := range fixed {
		if !ContentAddressed(u) {
			t.Errorf("ContentAddressed(%q) = false, want true", u)
		}
	}
	mutable := []string{
		"https://example.com/token.json",
		"https://flynnhq.com/token.json",
		"http://10.0.0.1/t.json",
		"",
	}
	for _, u := range mutable {
		if ContentAddressed(u) {
			t.Errorf("ContentAddressed(%q) = true, want false", u)
		}
	}
}

// TestFreshTreasuryIsAllowed is the regression for a bug the live devnet attack suite caught:
// a treasury that does not exist on-chain yet (a fresh wallet, or a brand-new Squads vault)
// is reported by the real RPC as rpc.ErrNotFound, an error, not a null value. An earlier
// version of the spendability guard treated that error as "could not check" and refused the
// mint, which would have blocked the exact multisig-vault case the feature exists to support.
// The absent treasury is the normal case and must be allowed.
func TestFreshTreasuryIsAllowed(t *testing.T) {
	f := &fakeRPC{
		confirm: true, lastValid: 1000, accountNotFoundFor: 1, // only the treasury pre-check is absent; the mint exists after minting
		mintData: revokedMintBytes(scaled(1_000_000, 9), 9),
	}
	e := custodyEngine(f, Mainnet)
	if _, _, err := e.Mint(context.Background(), custodySpec(solana.NewWallet().PublicKey())); err != nil {
		t.Fatalf("a treasury that does not exist on-chain yet was refused: %v", err)
	}
}
