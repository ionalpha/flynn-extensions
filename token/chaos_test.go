package token

import (
	"context"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"pgregory.net/rapid"
)

// TestMintUnderChaosNeverReportsAnUnsafeTokenAsSafe is the fault-injection gate. It drives the
// mint against a fake ledger while a rapid-chosen fault fires somewhere in the lifecycle: the
// submit is lost, a confirmation never arrives, the status read errors, the context is
// cancelled mid-flight, the mint reads back in an unexpected state. Across the whole space of
// where-it-breaks, ONE invariant must hold:
//
//	the engine reports success only when the on-chain mint is genuinely safe and complete,
//	i.e. mint authority revoked, no freeze authority, and holding exactly the requested supply.
//
// A false "success" on a token that is unsafe or under-supplied is the failure that loses
// money quietly, so it is the one the chaos matrix hunts for. A false failure (reporting an
// error on a mint that actually landed fine) is acceptable and expected: the honest answer to
// a lost confirmation is "I could not prove it", not "it worked".
func TestMintUnderChaosNeverReportsAnUnsafeTokenAsSafe(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		const wholeSupply = 1_000_000
		const decimals = 9
		scaledSupply := scaled(wholeSupply, decimals)

		// The fault: where, and what the chain looks like when we finally read it.
		failSend := rapid.Bool().Draw(t, "failSend")
		cancelAt := rapid.IntRange(0, 2).Draw(t, "cancelOnSend") // 0 = no cancel
		neverConfirm := rapid.Bool().Draw(t, "neverConfirm")
		statusErr := rapid.Bool().Draw(t, "sigStatusErr")

		// What the mint account reads back as, chosen independently of whether we "succeeded":
		// the point is that the REPORT must follow the CHAIN, not the RPC's happy path.
		authRevoked := rapid.Bool().Draw(t, "authRevoked")
		freezeAbsent := rapid.Bool().Draw(t, "freezeAbsent")
		supplyOnChain := rapid.SampledFrom([]uint64{0, scaledSupply, scaledSupply / 2}).Draw(t, "supply")

		mintData := mintBytesWithState(authRevoked, freezeAbsent, supplyOnChain, decimals)

		// A transaction that never confirms always, eventually, has its blockhash expire:
		// Solana blockhashes are only valid for ~150 slots. So "never confirms" is modelled
		// with the block height already past lastValidBlockHeight, which is what lets the
		// confirm loop terminate by expiry instead of waiting out the wall-clock lifecycle
		// budget. Modelling never-confirm-and-never-expire would be modelling a chain that
		// has stopped, which is a different failure (and one the lifecycle timeout covers).
		blockHeight := uint64(1)
		if neverConfirm {
			blockHeight = 1001 // past lastValid: the blockhash has expired
		}
		f := &fakeRPC{
			confirm:      !neverConfirm,
			lastValid:    1000,
			blockHeight:  blockHeight,
			failSendAt:   boolToIdx(failSend),
			cancelOnSend: cancelAt,
			sigStatusErr: statusErr,
			mintData:     mintData,
		}
		ctx, cancel := context.WithCancel(context.Background())
		f.cancel = cancel
		e := NewEngine(f, testPayer(), WithNetwork(Devnet))
		e.clk = firingClock{}

		mint, _, err := e.Mint(ctx, MintSpec{
			Name: "Chaos", Symbol: "CHS", MetadataURI: "ipfs://c",
			Decimals: decimals, Supply: wholeSupply,
			Treasury: solana.NewWallet().PublicKey(),
		})

		// The invariant. If the engine reported success, the chain state it verified must be
		// a genuinely safe, complete token. Anything less reported as success is the bug.
		if err == nil {
			if !authRevoked {
				t.Fatalf("reported success while the mint authority is LIVE on %s: the supply could be inflated", mint)
			}
			if !freezeAbsent {
				t.Fatalf("reported success while a freeze authority is present on %s", mint)
			}
			if supplyOnChain != scaledSupply {
				t.Fatalf("reported success while the on-chain supply is %d, not the requested %d", supplyOnChain, scaledSupply)
			}
		}
	})
}

// mintBytesWithState builds an 82-byte SPL Mint account with the chosen authority, freeze, and
// supply state, so a test can present the engine with any on-chain reality.
func mintBytesWithState(authRevoked, freezeAbsent bool, supply uint64, decimals uint8) []byte {
	b := revokedMintBytes(supply, decimals) // authority None, freeze None
	if !authRevoked {
		b[0] = 1 // mint_authority COption::Some
	}
	if !freezeAbsent {
		b[46] = 1 // freeze_authority COption::Some
	}
	return b
}

func boolToIdx(b bool) int {
	if b {
		return 1
	}
	return 0
}
