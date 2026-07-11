// Command token is the flynn token extension: an out-of-process MCP tool-server that
// creates and verifies fixed-supply SPL tokens on Solana with an anti-scam safety policy.
// flynn launches it as a sandboxed, egress-locked subprocess and mounts its tools
// (namespaced, capability-gated, governed at the dispatch waist on the flynn side).
//
// It speaks JSON-RPC over stdio: run it directly and it serves on stdin/stdout; flynn
// launches it the same way. Diagnostics go to stderr so they never corrupt the protocol
// stream on stdout.
//
// Configuration is read from the environment, never baked into the binary or a spec:
//
//	FLYNN_SOLANA_RPC   Solana JSON-RPC endpoint (defaults to devnet when unset).
//
// The signing key is NEVER held here. token_verify is read-only and needs no key. token_mint
// builds the transactions and runs the safety policy but holds no key: each transaction's
// payer signature is produced by flynn core with a vault-held key and handed back over the
// tool boundary (see the token package's Session). So a compromised extension can never obtain
// or misuse the key.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/ionalpha/flynn-extensions/mcpserver"
	"github.com/ionalpha/flynn-extensions/token"
)

// version is stamped at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	endpoint := os.Getenv("FLYNN_SOLANA_RPC")
	if endpoint == "" {
		endpoint = rpc.DevNet_RPC
		fmt.Fprintln(os.Stderr, "token extension: FLYNN_SOLANA_RPC unset, defaulting to devnet")
	}
	client := rpc.New(endpoint)

	s := mcpserver.New("token", version)
	s.Register(verifyTool(token.NewEngine(client, nil)))
	s.Register((&mintService{client: client, sessions: map[string]*token.Session{}}).tool())

	if err := s.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "token extension:", err)
		os.Exit(1)
	}
}

// verifyTool reports a mint's scam-relevant state: supply, decimals, and whether the mint
// and freeze authorities are revoked. A Token-2022 mint is reported as its own UNSAFE class
// rather than a read failure, because it can carry transfer hooks, fees, or a permanent
// delegate.
func verifyTool(eng *token.Engine) mcpserver.Tool {
	return mcpserver.Tool{
		Name:        "token_verify",
		Description: "Verify a Solana mint: report supply, decimals, and whether the mint and freeze authorities are revoked (a safe token has both revoked).",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"mint":{"type":"string"}},"required":["mint"]}`),
		Handler: func(ctx context.Context, arguments json.RawMessage) (string, error) {
			var a struct {
				Mint string `json:"mint"`
			}
			if err := json.Unmarshal(arguments, &a); err != nil {
				return "", fmt.Errorf("token_verify: bad input: %w", err)
			}
			pk, err := token.ParsePubkey(a.Mint)
			if err != nil {
				return "", fmt.Errorf("token_verify: bad mint address: %w", err)
			}
			st, err := eng.Verify(ctx, pk)
			if err != nil {
				if errors.Is(err, token.ErrToken2022Mint) {
					return fmt.Sprintf("mint %s: UNSAFE - Token-2022 mint that may carry transfer hooks, transfer fees, or a permanent delegate; not a plain fixed-supply SPL mint", pk), nil
				}
				return "", err
			}
			return fmt.Sprintf("mint %s: supply=%d decimals=%d mintAuthorityRevoked=%t freezeAbsent=%t",
				st.Mint, st.Supply, st.Decimals, st.SupplyFixed(), !st.Freezable()), nil
		},
	}
}

// mintService hosts token_mint. A mint is a resumable session: because the payer key lives in
// flynn core, the tool cannot complete a mint in one call. The first call starts a session and
// returns the first message core must sign; each later call delivers a signature and returns
// the next message or the final outcome. The service holds the in-flight sessions between
// calls. The mcpserver harness dispatches messages one at a time, so the map needs no locking
// for correctness; the mutex guards against any future concurrent driver.
type mintService struct {
	client   token.RPCClient
	mu       sync.Mutex
	seq      uint64
	sessions map[string]*token.Session
}

func (m *mintService) tool() mcpserver.Tool {
	return mcpserver.Tool{
		Name: "token_mint",
		Description: "Mint a new fixed-supply SPL token safely on Solana: create the mint, attach metadata, " +
			"mint the whole supply, then revoke the mint authority (freeze authority is never set). A scam-shaped " +
			"request is refused. This is a signing choreography: start with {payer,name,symbol,metadataUri,decimals,supply} " +
			"and the tool returns {session,sign:{pubkey,message}}; sign the message with the payer key and call again " +
			"with {session,signature} until it returns {done,mint}. Report a signing failure with {session,signError}.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{` +
			`"payer":{"type":"string"},"name":{"type":"string"},"symbol":{"type":"string"},"metadataUri":{"type":"string"},` +
			`"decimals":{"type":"integer"},"supply":{"type":"integer"},` +
			`"session":{"type":"string"},"signature":{"type":"string"},"signError":{"type":"string"}}}`),
		Handler: m.handle,
	}
}

func (m *mintService) handle(_ context.Context, arguments json.RawMessage) (string, error) {
	var a struct {
		Payer       string          `json:"payer"`
		Name        string          `json:"name"`
		Symbol      string          `json:"symbol"`
		MetadataURI string          `json:"metadataUri"`
		Decimals    uint8           `json:"decimals"`
		Supply      json.RawMessage `json:"supply"`
		Session     string          `json:"session"`
		Signature   string          `json:"signature"`
		SignError   string          `json:"signError"`
	}
	a.Decimals = 9
	if err := json.Unmarshal(arguments, &a); err != nil {
		return "", fmt.Errorf("token_mint: bad input: %w", err)
	}

	if a.Session == "" {
		payer, err := token.ParsePubkey(a.Payer)
		if err != nil {
			return "", fmt.Errorf("token_mint: bad payer address: %w", err)
		}
		supply, err := parseSupply(a.Supply)
		if err != nil {
			return "", fmt.Errorf("token_mint: %w", err)
		}
		s := token.StartMint(m.client, payer, token.MintSpec{
			Name: a.Name, Symbol: a.Symbol, MetadataURI: a.MetadataURI, Decimals: a.Decimals, Supply: supply,
		})
		return m.render(m.store(s), s)
	}

	m.mu.Lock()
	s := m.sessions[a.Session]
	m.mu.Unlock()
	if s == nil {
		return "", fmt.Errorf("token_mint: unknown session %q", a.Session)
	}
	var r token.SignResult
	switch {
	case a.SignError != "":
		r.Err = errors.New(a.SignError)
	default:
		sig, err := solana.SignatureFromBase58(a.Signature)
		if err != nil {
			return "", fmt.Errorf("token_mint: bad signature: %w", err)
		}
		r.Signature = sig
	}
	if err := s.Advance(r); err != nil {
		m.remove(a.Session)
		return "", fmt.Errorf("token_mint: %w", err)
	}
	return m.render(a.Session, s)
}

// render turns the session's current state into the tool's JSON reply: the next message to
// sign, or the final outcome. A completed session is dropped from the registry.
func (m *mintService) render(id string, s *token.Session) (string, error) {
	if out, done := s.Result(); done {
		m.remove(id)
		resp := map[string]any{"done": true, "mint": out.Mint.String()}
		if out.Err != nil {
			resp["error"] = out.Err.Error()
		}
		if len(out.Disclosures) > 0 {
			ds := make([]map[string]string, 0, len(out.Disclosures))
			for _, d := range out.Disclosures {
				ds = append(ds, map[string]string{"code": string(d.Code), "detail": d.Detail})
			}
			resp["disclosures"] = ds
		}
		return marshal(resp)
	}
	req, ok := s.Pending()
	if !ok {
		return "", fmt.Errorf("token_mint: session %q is neither done nor awaiting a signature", id)
	}
	return marshal(map[string]any{
		"session": id,
		"sign": map[string]string{
			"pubkey":  req.Pubkey.String(),
			"message": base64.StdEncoding.EncodeToString(req.Message),
		},
	})
}

func (m *mintService) store(s *token.Session) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	id := "mint-" + strconv.FormatUint(m.seq, 10)
	m.sessions[id] = s
	return id
}

func (m *mintService) remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
}

func marshal(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("token_mint: encode reply: %w", err)
	}
	return string(b), nil
}

// parseSupply accepts the supply as a JSON number or a decimal string, so a caller whose JSON
// encoder cannot hold a uint64 in a number (many do not, above 2^53) can pass it as a string
// without losing precision. An absent supply is zero, which the engine refuses up front.
func parseSupply(raw json.RawMessage) (uint64, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, nil
	}
	s := string(raw)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("supply must be a non-negative integer: %w", err)
	}
	return n, nil
}
