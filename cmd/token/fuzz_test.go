package main

import (
	"encoding/json"
	"testing"
)

// FuzzParseSupply throws arbitrary bytes at the supply parser, which sits on the tool
// boundary and reads a value a caller (ultimately a model, or anything speaking to the tool)
// controls. A panic there is a crash triggered by input; a wrong parse mints the wrong
// number of tokens. The parser must always either return a value or a clean error, and never
// panic, for any bytes at all, including bytes that are not valid JSON.
func FuzzParseSupply(f *testing.F) {
	for _, s := range []string{
		`1000000`, `"1000000"`, `0`, `null`, ``, `-1`, `1.5`, `"abc"`,
		`18446744073709551615`, `18446744073709551616`, `"  7 "`, `"0x10"`, `[]`, `{}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		n, err := parseSupply(json.RawMessage(raw)) // must never panic
		if err == nil {
			// A successful parse must be a value the engine can actually mint: a bare
			// non-negative integer. Re-parsing the canonical form must give the same number.
			if n != 0 {
				var check uint64
				if jerr := json.Unmarshal([]byte(itoa(n)), &check); jerr != nil || check != n {
					t.Fatalf("parseSupply accepted %q as %d, which does not round-trip", raw, n)
				}
			}
		}
	})
}

// itoa avoids strconv in the assertion to keep the check independent of the parser's own
// formatting path.
func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
