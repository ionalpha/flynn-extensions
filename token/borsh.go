package token

import (
	"bytes"
	"encoding/binary"
)

// Metaplex Token Metadata instruction discriminators (single-byte enum index into
// MetadataInstruction).
const (
	// ixCreate is the modern Create (CreateArgs::V1). It initializes the Mint account AND
	// the Metadata account in one instruction, which is what lets the whole mint be atomic.
	// It supersedes CreateMetadataAccountV3 (33), which is deprecated.
	ixCreate = 42
)

// tokenStandardFungible is TokenStandard::Fungible: a plain divisible token with a supply,
// as opposed to the NonFungible variants (which additionally require a master edition).
const tokenStandardFungible = 2

// borshString writes a Borsh string: u32 LE length prefix then the raw bytes.
func borshString(buf *bytes.Buffer, s string) {
	// #nosec G115 -- these are token metadata fields (name, symbol, uri), whose
	// lengths are bounded far below uint32 by validateMetadata.
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(s)))
	buf.WriteString(s)
}

// createV1Data builds the instruction data for Create (CreateArgs::V1) describing an
// immutable, fixed-supply fungible token.
//
// The layout is the Borsh encoding of:
//
//	CreateArgs::V1 { asset_data: AssetData, decimals: Option<u8>, print_supply: Option<PrintSupply> }
//
// where AssetData is name, symbol, uri, seller_fee_basis_points, creators,
// primary_sale_happened, is_mutable, token_standard, collection, uses, collection_details,
// rule_set. Every optional field is None and every scam-adjacent field is zero: this
// function cannot express a token with creators, fees, or mutable metadata, because none of
// those are parameters.
//
// print_supply is None: it belongs to editions of non-fungibles and is not a fungible
// concept. The supply of this token is set by minting into the treasury and then revoking
// the mint authority, which is what makes it provably fixed.
func createV1Data(name, symbol, uri string, decimals uint8) []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(ixCreate)
	buf.WriteByte(0) // CreateArgs variant = V1

	// --- AssetData ---
	borshString(buf, name)
	borshString(buf, symbol)
	borshString(buf, uri)
	_ = binary.Write(buf, binary.LittleEndian, uint16(0)) // seller_fee_basis_points: no royalty
	buf.WriteByte(0)                                      // creators: None
	buf.WriteByte(0)                                      // primary_sale_happened: false
	buf.WriteByte(0)                                      // is_mutable: FALSE - the identity is permanently locked
	buf.WriteByte(tokenStandardFungible)                  // token_standard: Fungible
	buf.WriteByte(0)                                      // collection: None
	buf.WriteByte(0)                                      // uses: None
	buf.WriteByte(0)                                      // collection_details: None
	buf.WriteByte(0)                                      // rule_set: None - no programmable transfer rules

	// --- decimals: Option<u8> = Some(decimals) ---
	buf.WriteByte(1)
	buf.WriteByte(decimals)

	// --- print_supply: Option<PrintSupply> = None ---
	buf.WriteByte(0)

	return buf.Bytes()
}
