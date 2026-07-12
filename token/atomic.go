package token

import (
	"fmt"

	solana "github.com/gagliardetto/solana-go"
	ata "github.com/gagliardetto/solana-go/programs/associated-token-account"
	"github.com/gagliardetto/solana-go/programs/token"
)

// sysvarInstructions is the instructions sysvar, which Token Metadata's Create requires so
// it can inspect the surrounding transaction.
var sysvarInstructions = solana.MustPublicKeyFromBase58("Sysvar1nstructions1111111111111111111111111")

// buildMint assembles the ENTIRE token lifecycle as one list of instructions, to be sent as
// a single transaction:
//
//	create   Token Metadata's Create (CreateArgs::V1) initializes the mint AND its immutable
//	         metadata in one instruction, with the payer as the transient mint authority and
//	         no freeze authority.
//	ata      the treasury's associated token account, idempotently.
//	mintTo   the whole supply, into that account.
//	revoke   SetAuthority(MintTokens -> None), which permanently fixes the supply.
//
// One transaction is the point. Solana transactions are atomic: every instruction lands or
// none does. So there is no state in which the mint exists with a live mint authority, and
// no window - not one slot - in which the payer's hot key could inflate the supply. Either
// the chain holds a finished, fixed-supply, immutable token, or it holds nothing at all.
//
// The alternative, running these as four transactions, cannot offer that. Between the first
// and the last, the payer IS the mint authority, and a crash, a stalled cluster, or a
// compromised key in that window leaves a token that can be inflated. Atomicity deletes the
// entire class of problem rather than cleaning up after it.
func (e *Engine) buildMint(mint, treasury solana.PublicKey, s MintSpec) ([]solana.Instruction, error) {
	payer := e.payer.PublicKey()

	metadata, err := metadataPDA(mint)
	if err != nil {
		return nil, fmt.Errorf("metadata PDA: %w", err)
	}

	// Create: initializes the mint and writes immutable metadata. The update authority is
	// the treasury, so the payer's hot key retains nothing at all once this transaction
	// lands. accounts, in the order the program expects:
	//   metadata(w), masterEdition(optional - absent for a fungible), mint(w,s),
	//   authority(s), payer(w,s), updateAuthority, systemProgram, sysvarInstructions,
	//   splTokenProgram
	create := solana.NewInstruction(metadataProgram, solana.AccountMetaSlice{
		solana.Meta(metadata).WRITE(),
		solana.Meta(metadataProgram), // master edition: none for a fungible; the program is passed as the "empty" placeholder
		solana.Meta(mint).WRITE().SIGNER(),
		solana.Meta(payer).SIGNER(),
		solana.Meta(payer).WRITE().SIGNER(),
		solana.Meta(treasury),
		solana.Meta(solana.SystemProgramID),
		solana.Meta(sysvarInstructions),
		solana.Meta(token.ProgramID),
	}, createV1Data(s.Name, s.Symbol, s.MetadataURI, s.Decimals))

	dest, _, err := solana.FindAssociatedTokenAddress(treasury, mint)
	if err != nil {
		return nil, fmt.Errorf("derive ATA: %w", err)
	}
	// CreateIdempotent, not Create: anyone may pre-create the treasury's token account for
	// the price of rent, and plain Create FAILS if it already exists. In a single-transaction
	// mint that failure would abort the whole thing, so a front-runner could block the mint
	// indefinitely. Idempotent makes the front-run a no-op.
	createATA, err := ata.NewCreateIdempotentInstructionBuilder().
		SetPayer(payer).SetWallet(treasury).SetMint(mint).ValidateAndBuild()
	if err != nil {
		return nil, fmt.Errorf("build create ATA: %w", err)
	}

	amount, err := scaledAmount(s.Supply, s.Decimals)
	if err != nil {
		return nil, err
	}
	mintTo, err := token.NewMintToInstructionBuilder().
		SetAmount(amount).SetMintAccount(mint).SetDestinationAccount(dest).SetAuthorityAccount(payer).
		ValidateAndBuild()
	if err != nil {
		return nil, fmt.Errorf("build mint-to: %w", err)
	}

	// Revoke the FREEZE authority. Token Metadata's Create initializes the mint with a freeze
	// authority set (the old hand-rolled InitializeMint2 simply never set one). A freeze
	// authority is the honeypot lever: it lets the issuer freeze holders so they cannot sell.
	// Leaving it would make every token this engine mints scam-shaped, so it is revoked in
	// the same transaction that creates the mint, and can never have been used.
	//
	// This was not a theoretical risk. The first devnet run of the atomic mint came back
	// "post-mint verify failed: a freeze authority is present", which is exactly what the
	// verify-against-chain step exists to catch.
	revokeFreeze, err := token.NewSetAuthorityInstructionBuilder().
		SetAuthorityType(token.AuthorityFreezeAccount).
		SetSubjectAccount(mint).
		SetAuthorityAccount(payer).
		ValidateAndBuild()
	if err != nil {
		return nil, fmt.Errorf("build revoke-freeze: %w", err)
	}

	// Revoke the MINT authority. NewAuthority is deliberately left unset, which encodes
	// COption::None. Setting the mint authority to None is irreversible on-chain: no key,
	// program, or upgrade can restore it, and MintTo can never succeed again. This is what
	// "fixed supply" means, and it happens in the same transaction as the mint, so it cannot
	// be skipped, lost, or raced. It must come AFTER mintTo, which needs the authority.
	revokeMint, err := token.NewSetAuthorityInstructionBuilder().
		SetAuthorityType(token.AuthorityMintTokens).
		SetSubjectAccount(mint).
		SetAuthorityAccount(payer).
		ValidateAndBuild()
	if err != nil {
		return nil, fmt.Errorf("build set-authority: %w", err)
	}

	return []solana.Instruction{create, createATA, mintTo, revokeFreeze, revokeMint}, nil
}
