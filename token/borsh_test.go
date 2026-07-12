package token

import (
	"encoding/binary"
	"testing"

	"pgregory.net/rapid"
)

// readBorshString reads a Borsh string (u32 LE length then bytes) at off, returning
// the decoded string and the offset just past it.
func readBorshString(b []byte, off int) (string, int) {
	n := int(binary.LittleEndian.Uint32(b[off:]))
	off += 4
	return string(b[off : off+n]), off + n
}

// TestCreateV1DataRoundTrip checks, for arbitrary name/symbol/uri/decimals, that createV1Data
// leads with the Create discriminator and the V1 variant, encodes the three strings exactly
// (correct length prefixes, exact bytes, right order), and then pins every field that makes
// the resulting token safe. A length-prefix bug, or a field silently shifting position, would
// surface here across the whole input space - and a shifted field is exactly how a byte meant
// to say "immutable" could come to mean something else.
func TestCreateV1DataRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := rapid.String().Draw(t, "name")
		symbol := rapid.String().Draw(t, "symbol")
		uri := rapid.String().Draw(t, "uri")
		decimals := rapid.Uint8().Draw(t, "decimals")

		b := createV1Data(name, symbol, uri, decimals)

		// [ixCreate][CreateArgs variant = V1 (0)]
		if len(b) < 2 || b[0] != ixCreate || b[1] != 0 {
			t.Fatalf("create header wrong: %v", b[:min(2, len(b))])
		}
		gotName, off := readBorshString(b, 2)
		gotSymbol, off := readBorshString(b, off)
		gotURI, off := readBorshString(b, off)
		if gotName != name || gotSymbol != symbol || gotURI != uri {
			t.Fatalf("round-trip mismatch: name=%q symbol=%q uri=%q", gotName, gotSymbol, gotURI)
		}

		// AssetData continues: seller_fee_basis_points (u16), creators (Option), then
		// primary_sale_happened, is_mutable, token_standard.
		if fee := binary.LittleEndian.Uint16(b[off:]); fee != 0 {
			t.Fatalf("seller_fee_basis_points = %d, want 0: a royalty on a fungible token is a transfer tax", fee)
		}
		off += 2
		if b[off] != 0 {
			t.Fatalf("creators = %d, want 0 (None)", b[off])
		}
		off++
		if b[off] != 0 {
			t.Fatalf("primary_sale_happened = %d, want 0", b[off])
		}
		off++
		// The field the whole safety claim rests on: an immutable identity can never be
		// repainted into another project's name/symbol after the token is reported safe.
		if b[off] != 0 {
			t.Fatalf("is_mutable = %d, want 0: the identity must be permanently locked", b[off])
		}
		off++
		if b[off] != tokenStandardFungible {
			t.Fatalf("token_standard = %d, want %d (Fungible)", b[off], tokenStandardFungible)
		}
		off++
		// collection, uses, collection_details, rule_set: all None. rule_set in particular
		// must be None: a rule set is a programmable-transfer hook by another name.
		for i, field := range []string{"collection", "uses", "collection_details", "rule_set"} {
			if b[off+i] != 0 {
				t.Fatalf("%s = %d, want 0 (None)", field, b[off+i])
			}
		}
		off += 4

		// decimals: Option<u8> = Some(decimals)
		if b[off] != 1 || b[off+1] != decimals {
			t.Fatalf("decimals = %v, want Some(%d)", b[off:off+2], decimals)
		}
		off += 2
		// print_supply: Option<PrintSupply> = None (an edition concept, not a fungible one)
		if b[off] != 0 {
			t.Fatalf("print_supply = %d, want 0 (None)", b[off])
		}
		if off+1 != len(b) {
			t.Fatalf("trailing bytes after print_supply: %d unread", len(b)-off-1)
		}
	})
}
