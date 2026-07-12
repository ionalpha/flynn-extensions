package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"
	tokenprog "github.com/gagliardetto/solana-go/programs/token"

	"github.com/ionalpha/flynn-extensions/clock"
	"github.com/ionalpha/flynn-extensions/token"
)

// firingClock is the timing source these tests give a mint: every wait is already elapsed. The
// engine's poll loops therefore run at full speed, and the test exercises the choreography rather
// than the two-second confirmation cadence. Every stop condition is chain state, not time, so this
// changes how long the test takes and nothing about what it proves.
type firingClock struct{ clock.System }

func (firingClock) After(time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	ch <- time.Time{}
	return ch
}

// The tools hold no RPC client, so these tests drive them the way flynn core does: they answer
// the tool's host calls. Each fetch is answered with a JSON-RPC response built here, at the byte
// level, which means the extension's whole transport (marshal the request, park, decode the
// response) is exercised and not just the engine behind it. Each signature is produced with a
// test key that stands in for core's vault-held one.

// fakeNode answers Solana JSON-RPC requests on the wire, standing in for the endpoint core holds.
// It answers only the six methods the engine calls; anything else is an explicit error, so a tool
// that reached for an unexpected method fails loudly rather than silently.
type fakeNode struct {
	owner    solana.PublicKey // the mint account's owner program
	mintData []byte           // the mint account's data
	calls    []string         // every method it was asked for, in order
}

func (n *fakeNode) answer(body []byte) ([]byte, error) {
	var req struct {
		ID     int    `json:"id"`
		Method string `json:"method"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("fake node: request is not JSON-RPC: %w", err)
	}
	n.calls = append(n.calls, req.Method)

	var result string
	switch req.Method {
	case "getMinimumBalanceForRentExemption":
		result = `1000000`
	case "getLatestBlockhash":
		result = `{"context":{"slot":1},"value":{"blockhash":"` + solana.Hash{1}.String() + `","lastValidBlockHeight":1000}}`
	case "sendTransaction":
		result = `"` + solana.Signature{2}.String() + `"`
	case "getSignatureStatuses":
		result = `{"context":{"slot":1},"value":[{"slot":1,"err":null,"confirmationStatus":"finalized"}]}`
	case "getBlockHeight":
		result = `1`
	case "getAccountInfo":
		owner := n.owner
		if owner.IsZero() {
			owner = tokenprog.ProgramID
		}
		data := base64.StdEncoding.EncodeToString(n.mintData)
		result = `{"context":{"slot":1},"value":{"lamports":1,"owner":"` + owner.String() +
			`","data":["` + data + `","base64"],"executable":false,"rentEpoch":0}}`
	default:
		return nil, fmt.Errorf("fake node: unexpected method %q", req.Method)
	}
	return fmt.Appendf(nil, `{"jsonrpc":"2.0","id":%d,"result":%s}`, req.ID, result), nil
}

// handler is the tool entry point under test.
type handler func(context.Context, json.RawMessage) (string, error)

// drive plays flynn core's host-call loop against a tool: it starts the call, then services every
// host call the tool hands out (answering a fetch from the fake node, signing a message with the
// payer key) until the tool returns a terminal result. It returns that result. signErr, when set,
// is reported to the tool in place of the FIRST signature, so a test can drive the engine's
// signing-failure path.
func drive(t *testing.T, h handler, node *fakeNode, payer solana.PrivateKey, start string, signErr string) string {
	t.Helper()
	next := start
	// A mint is 4 signatures and a few dozen reads; a bound well above that keeps a broken
	// choreography from hanging the test instead of failing it.
	for range 200 {
		out, err := h(context.Background(), json.RawMessage(next))
		if err != nil {
			t.Fatalf("tool returned an error: %v", err)
		}
		var reply struct {
			Session string `json:"session"`
			Sign    *struct {
				Message string `json:"message"`
			} `json:"sign"`
			Fetch *struct {
				Body string `json:"body"`
			} `json:"fetch"`
		}
		// A reply that is not a host call (not JSON, or JSON with neither block) is terminal.
		if err := json.Unmarshal([]byte(out), &reply); err != nil || (reply.Sign == nil && reply.Fetch == nil) {
			return out
		}
		switch {
		case reply.Sign != nil:
			if signErr != "" {
				next = `{"session":"` + reply.Session + `","signError":"` + signErr + `"}`
				signErr = ""
				continue
			}
			msg, err := base64.StdEncoding.DecodeString(reply.Sign.Message)
			if err != nil {
				t.Fatalf("sign message is not base64: %q", reply.Sign.Message)
			}
			sig, err := payer.Sign(msg)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			next = `{"session":"` + reply.Session + `","signature":"` + base64.StdEncoding.EncodeToString(sig[:]) + `"}`
		case reply.Fetch != nil:
			body, err := base64.StdEncoding.DecodeString(reply.Fetch.Body)
			if err != nil {
				t.Fatalf("fetch body is not base64: %q", reply.Fetch.Body)
			}
			res, err := node.answer(body)
			if err != nil {
				t.Fatalf("fake node: %v", err)
			}
			next = `{"session":"` + reply.Session + `","response":"` + base64.StdEncoding.EncodeToString(res) + `"}`
		}
	}
	t.Fatal("the tool never reached a terminal result")
	return ""
}

// revokedMint builds the 82-byte SPL Mint layout for an initialized mint with both
// authorities revoked (COption::None) and the given supply/decimals.
func revokedMint(supply uint64, decimals uint8) []byte {
	b := make([]byte, 82)
	binary.LittleEndian.PutUint64(b[36:44], supply)
	b[44] = decimals
	b[45] = 1 // is_initialized
	return b
}

const someMint = "So11111111111111111111111111111111111111112"

func runVerify(t *testing.T, node *fakeNode) string {
	t.Helper()
	return drive(t, newVerifyService().handle, node, solana.PrivateKey{}, `{"mint":"`+someMint+`"}`, "")
}

// TestVerifyReadsTheChainThroughTheHost proves the read path never touches a network of its own:
// the tool hands out a getAccountInfo request as opaque bytes, the driver answers it, and the tool
// renders the verdict. If the extension still held an RPC client this test could not answer it.
func TestVerifyReadsTheChainThroughTheHost(t *testing.T) {
	node := &fakeNode{owner: tokenprog.ProgramID, mintData: revokedMint(1_000_000, 9)}
	out := runVerify(t, node)

	if !strings.Contains(out, "mintAuthorityRevoked=true") || !strings.Contains(out, "freezeAbsent=true") {
		t.Fatalf("safe mint not reported as revoked+freeze-free: %q", out)
	}
	if !strings.Contains(out, "supply=1000000") || !strings.Contains(out, "decimals=9") {
		t.Fatalf("safe mint supply/decimals not rendered: %q", out)
	}
	if len(node.calls) != 1 || node.calls[0] != "getAccountInfo" {
		t.Fatalf("verify should be exactly one getAccountInfo through the host, got %v", node.calls)
	}
}

// TestVerifyRendersToken2022AsUnsafe proves the handler renders a Token-2022 mint as an
// UNSAFE verdict (a normal tool result), never as a read failure.
func TestVerifyRendersToken2022AsUnsafe(t *testing.T) {
	out := runVerify(t, &fakeNode{
		owner:    solana.MustPublicKeyFromBase58("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"),
		mintData: revokedMint(0, 9),
	})
	if !strings.Contains(out, "UNSAFE") || !strings.Contains(out, "Token-2022") {
		t.Fatalf("did not report the Token-2022 mint as UNSAFE: %q", out)
	}
}

// TestVerifyRejectsBadAddress proves a non-base58 mint argument is a tool error, not a panic, and
// that it is refused before any host call is made.
func TestVerifyRejectsBadAddress(t *testing.T) {
	node := &fakeNode{}
	if _, err := newVerifyService().handle(context.Background(), []byte(`{"mint":"not-an-address"}`)); err == nil {
		t.Fatal("expected an error for a malformed mint address")
	}
	if len(node.calls) != 0 {
		t.Fatalf("a malformed address must be refused before any host call, saw %v", node.calls)
	}
}

// TestMintToolChoreography drives the full token_mint JSON protocol over the host boundary: every
// chain read and every transaction submission crosses out as a fetch, every transaction crosses
// out as a signature, and the mint completes. It proves the tool-boundary encoding, the session
// registry, and that the extension needs neither a key nor a network to mint.
func TestMintToolChoreography(t *testing.T) {
	payer, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatalf("generate payer: %v", err)
	}
	const supply = 1_000_000
	node := &fakeNode{mintData: revokedMint(scaled(supply, 9), 9)}
	hostKey := base64.StdEncoding.EncodeToString(payer.PublicKey().Bytes())

	m := newMintService(token.WithClock(firingClock{}))
	start := `{"_hostKey":"` + hostKey + `","name":"Example Token","symbol":"EXMP",` +
		`"metadataUri":"https://example.com/token.json","decimals":9,"supply":"1000000"}`
	out := drive(t, m.handle, node, payer, start, "")

	var done struct {
		Done  bool   `json:"done"`
		Mint  string `json:"mint"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &done); err != nil {
		t.Fatalf("terminal reply is not JSON: %v (%s)", err, out)
	}
	if !done.Done || done.Error != "" {
		t.Fatalf("mint did not complete cleanly: %s", out)
	}
	if done.Mint == "" {
		t.Fatalf("clean mint returned no address: %s", out)
	}
	// The mint really went through the host: it could not have submitted a transaction otherwise.
	if !containsCall(node.calls, "sendTransaction") {
		t.Fatalf("no transaction was submitted through the host: %v", node.calls)
	}
	if len(m.reg.sessions) != 0 {
		t.Fatalf("completed session was not dropped from the registry: %d left", len(m.reg.sessions))
	}
}

// TestMintToolDeliversSignFailure proves a signing failure reported by the host is delivered into
// the lifecycle and drives it to a terminal outcome carrying the error, rather than hanging.
func TestMintToolDeliversSignFailure(t *testing.T) {
	payer, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatalf("generate payer: %v", err)
	}
	node := &fakeNode{mintData: revokedMint(0, 9)}
	hostKey := base64.StdEncoding.EncodeToString(payer.PublicKey().Bytes())

	m := newMintService(token.WithClock(firingClock{}))
	start := `{"_hostKey":"` + hostKey + `","name":"Example Token","symbol":"EXMP",` +
		`"metadataUri":"https://example.com/token.json","decimals":9,"supply":"1000000"}`
	out := drive(t, m.handle, node, payer, start, "vault unavailable")

	var done struct {
		Done  bool   `json:"done"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &done); err != nil {
		t.Fatalf("terminal reply is not JSON: %v (%s)", err, out)
	}
	if !done.Done || done.Error == "" {
		t.Fatalf("expected a terminal outcome carrying the signing error, got: %s", out)
	}
	if len(m.reg.sessions) != 0 {
		t.Fatalf("failed session was not dropped from the registry: %d left", len(m.reg.sessions))
	}
}

// TestMintToolRejectsBadInput covers the parse/guard paths of the tool boundary.
func TestMintToolRejectsBadInput(t *testing.T) {
	m := newMintService()
	if _, err := m.handle(context.Background(), []byte(`{"_hostKey":"not-base64!!","supply":"1"}`)); err == nil {
		t.Fatal("expected an error for a bad host key")
	}
	if _, err := m.handle(context.Background(), []byte(`{"session":"nope","signature":"x"}`)); err == nil {
		t.Fatal("expected an error for an unknown session")
	}
}

func containsCall(calls []string, want string) bool {
	for _, c := range calls {
		if c == want {
			return true
		}
	}
	return false
}

// scaled is the whole-token supply in base units.
func scaled(whole uint64, decimals uint8) uint64 {
	for range decimals {
		whole *= 10
	}
	return whole
}
