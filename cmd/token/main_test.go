package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	tokenprog "github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/ionalpha/flynn-extensions/token"
)

// fakeRPC implements token.RPCClient for the verify handler test. Verify only reads an
// account, so GetAccountInfoWithOpts is the only method that carries behaviour; the rest
// return errors to prove the read path never touches them.
type fakeRPC struct {
	owner solana.PublicKey
	data  []byte
}

func (f fakeRPC) GetAccountInfoWithOpts(context.Context, solana.PublicKey, *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error) {
	return &rpc.GetAccountInfoResult{Value: &rpc.Account{Owner: f.owner, Data: rpc.DataBytesOrJSONFromBytes(f.data)}}, nil
}

func (fakeRPC) GetLatestBlockhash(context.Context, rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error) {
	return nil, errors.New("unexpected call")
}

func (fakeRPC) GetBlockHeight(context.Context, rpc.CommitmentType) (uint64, error) {
	return 0, errors.New("unexpected call")
}

func (fakeRPC) SendTransaction(context.Context, *solana.Transaction) (solana.Signature, error) {
	return solana.Signature{}, errors.New("unexpected call")
}

func (fakeRPC) GetSignatureStatuses(context.Context, bool, ...solana.Signature) (*rpc.GetSignatureStatusesResult, error) {
	return nil, errors.New("unexpected call")
}

func (fakeRPC) GetMinimumBalanceForRentExemption(context.Context, uint64, rpc.CommitmentType) (uint64, error) {
	return 0, errors.New("unexpected call")
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

func runVerify(t *testing.T, rpcClient token.RPCClient) string {
	t.Helper()
	eng := token.NewEngine(rpcClient, nil)
	out, err := verifyTool(eng).Handler(context.Background(), []byte(`{"mint":"`+someMint+`"}`))
	if err != nil {
		t.Fatalf("token_verify returned a transport error instead of a verdict: %v", err)
	}
	return out
}

// TestVerifyRendersToken2022AsUnsafe proves the handler renders a Token-2022 mint as an
// UNSAFE verdict (a normal tool result), never as a read failure.
func TestVerifyRendersToken2022AsUnsafe(t *testing.T) {
	out := runVerify(t, fakeRPC{owner: solana.MustPublicKeyFromBase58("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")})
	if !strings.Contains(out, "UNSAFE") || !strings.Contains(out, "Token-2022") {
		t.Fatalf("did not report the Token-2022 mint as UNSAFE: %q", out)
	}
}

// TestVerifyRendersSafeMint proves the handler reports a revoked, freeze-free mint as safe.
func TestVerifyRendersSafeMint(t *testing.T) {
	out := runVerify(t, fakeRPC{owner: tokenprog.ProgramID, data: revokedMint(1_000_000, 9)})
	if !strings.Contains(out, "mintAuthorityRevoked=true") || !strings.Contains(out, "freezeAbsent=true") {
		t.Fatalf("safe mint not reported as revoked+freeze-free: %q", out)
	}
	if !strings.Contains(out, "supply=1000000") || !strings.Contains(out, "decimals=9") {
		t.Fatalf("safe mint supply/decimals not rendered: %q", out)
	}
}

// TestVerifyRejectsBadAddress proves a non-base58 mint argument is a tool error, not a panic.
func TestVerifyRejectsBadAddress(t *testing.T) {
	eng := token.NewEngine(fakeRPC{}, nil)
	if _, err := verifyTool(eng).Handler(context.Background(), []byte(`{"mint":"not-an-address"}`)); err == nil {
		t.Fatal("expected an error for a malformed mint address")
	}
}

// mintFakeRPC answers every method the mint lifecycle uses so a session reaches its first
// payer-signature request without real network or delay. The account read returns a revoked
// mint so an abort's safety check is satisfied immediately.
type mintFakeRPC struct{ owner solana.PublicKey }

func (mintFakeRPC) GetMinimumBalanceForRentExemption(context.Context, uint64, rpc.CommitmentType) (uint64, error) {
	return 1_000_000, nil
}

func (mintFakeRPC) GetLatestBlockhash(context.Context, rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error) {
	return &rpc.GetLatestBlockhashResult{Value: &rpc.LatestBlockhashResult{Blockhash: solana.Hash{1}, LastValidBlockHeight: 1000}}, nil
}

func (mintFakeRPC) SendTransaction(context.Context, *solana.Transaction) (solana.Signature, error) {
	return solana.Signature{2}, nil
}

func (mintFakeRPC) GetSignatureStatuses(context.Context, bool, ...solana.Signature) (*rpc.GetSignatureStatusesResult, error) {
	return &rpc.GetSignatureStatusesResult{Value: []*rpc.SignatureStatusesResult{{ConfirmationStatus: rpc.ConfirmationStatusFinalized}}}, nil
}

func (mintFakeRPC) GetBlockHeight(context.Context, rpc.CommitmentType) (uint64, error) { return 0, nil }

func (f mintFakeRPC) GetAccountInfoWithOpts(context.Context, solana.PublicKey, *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error) {
	owner := f.owner
	if owner.IsZero() {
		owner = tokenprog.ProgramID
	}
	return &rpc.GetAccountInfoResult{Value: &rpc.Account{Owner: owner, Data: rpc.DataBytesOrJSONFromBytes(revokedMint(0, 9))}}, nil
}

// TestMintToolChoreography drives the token_mint JSON protocol: a start call returns a signable
// message for the payer, and reporting a signing failure drives the session to a terminal
// outcome. It proves the tool-boundary encoding and the session registry, over the same engine
// the session tests cover deterministically.
func TestMintToolChoreography(t *testing.T) {
	m := &mintService{client: mintFakeRPC{}, sessions: map[string]*token.Session{}}
	payer := solana.NewWallet().PublicKey()
	hostKey := base64.StdEncoding.EncodeToString(payer.Bytes())

	start := `{"_hostKey":"` + hostKey + `","name":"Flynn","symbol":"FLYNN","metadataUri":"https://example.com/f.json","decimals":9,"supply":"1000000"}`
	out, err := m.handle(context.Background(), []byte(start))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	var first struct {
		Session string `json:"session"`
		Sign    struct {
			Message string `json:"message"`
		} `json:"sign"`
	}
	if err := json.Unmarshal([]byte(out), &first); err != nil {
		t.Fatalf("start reply is not JSON: %v (%s)", err, out)
	}
	if first.Session == "" {
		t.Fatalf("start did not open a session: %s", out)
	}
	if _, derr := base64.StdEncoding.DecodeString(first.Sign.Message); derr != nil || first.Sign.Message == "" {
		t.Fatalf("sign message is not base64 bytes: %q", first.Sign.Message)
	}

	// Report that core could not sign; the session must reach a terminal outcome.
	cont := `{"session":"` + first.Session + `","signError":"vault unavailable"}`
	out2, err := m.handle(context.Background(), []byte(cont))
	if err != nil {
		t.Fatalf("continue: %v", err)
	}
	var done struct {
		Done  bool   `json:"done"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(out2), &done); err != nil {
		t.Fatalf("continue reply is not JSON: %v (%s)", err, out2)
	}
	if !done.Done || done.Error == "" {
		t.Fatalf("expected a terminal outcome carrying the error, got: %s", out2)
	}
	if len(m.sessions) != 0 {
		t.Fatalf("completed session was not dropped from the registry: %d left", len(m.sessions))
	}
}

// TestMintToolRejectsBadInput covers the parse/guard paths of the tool boundary.
func TestMintToolRejectsBadInput(t *testing.T) {
	m := &mintService{client: mintFakeRPC{}, sessions: map[string]*token.Session{}}
	if _, err := m.handle(context.Background(), []byte(`{"_hostKey":"not-base64!!","supply":"1"}`)); err == nil {
		t.Fatal("expected an error for a bad host key")
	}
	if _, err := m.handle(context.Background(), []byte(`{"session":"nope","signature":"x"}`)); err == nil {
		t.Fatal("expected an error for an unknown session")
	}
}
