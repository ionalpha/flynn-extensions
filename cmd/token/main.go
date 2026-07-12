// Command token is the flynn token extension: an out-of-process MCP tool-server that
// creates and verifies fixed-supply SPL tokens on Solana with an anti-scam safety policy.
// flynn launches it as a sandboxed subprocess and mounts its tools (namespaced,
// capability-gated, governed at the dispatch waist on the flynn side).
//
// It speaks JSON-RPC over stdio: run it directly and it serves on stdin/stdout; flynn launches
// it the same way. Diagnostics go to stderr so they never corrupt the protocol stream on stdout.
//
// THIS PROCESS HOLDS NO KEY AND NO NETWORK.
//
// Neither authority a token mint needs lives here. The signing key stays in the flynn vault:
// each transaction is built here against the key's PUBLIC half and handed to the host to sign,
// so a compromised extension can never obtain or misuse it. The network stays with the host
// too: this process has no RPC endpoint, no socket, and no way to name a destination. Every
// Solana JSON-RPC request it makes is handed to the host as opaque bytes, and the host sends it
// to the endpoint the OPERATOR configured and returns the response.
//
// So flynn launches this binary with egress fully denied, on every platform. There is no
// address it can exfiltrate to, no internal service it can reach, and no way to redirect the
// bytes it does send: the only thing that leaves is a request the host agreed to send, to the
// one endpoint the host itself holds. That is why both tools below are resumable sessions
// rather than plain calls: each one runs until it needs the host to sign or to send, hands out
// the bytes, and continues when the host answers.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/ionalpha/flynn-extensions/mcpserver"
	"github.com/ionalpha/flynn-extensions/token"
)

// version is stamped at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	s := mcpserver.New("token", version)
	s.Register(newVerifyService().tool())
	s.Register(newMintService().tool())

	if err := s.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "token extension:", err)
		os.Exit(1)
	}
}

// sessionRegistry holds the lifecycles that are in flight between calls. Because neither tool
// can complete in one call (each must pause for the host to sign or to send), a tool call
// returns a host-call message carrying a session id, and the next call resumes that session.
// The mcpserver harness dispatches messages one at a time, so the map needs no locking for
// correctness; the mutex guards against any future concurrent driver.
type sessionRegistry[S any] struct {
	prefix   string
	mu       sync.Mutex
	seq      uint64
	sessions map[string]*S
}

func newRegistry[S any](prefix string) *sessionRegistry[S] {
	return &sessionRegistry[S]{prefix: prefix, sessions: map[string]*S{}}
}

func (r *sessionRegistry[S]) store(s *S) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	id := r.prefix + strconv.FormatUint(r.seq, 10)
	r.sessions[id] = s
	return id
}

func (r *sessionRegistry[S]) get(id string) *S {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[id]
}

func (r *sessionRegistry[S]) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, id)
}

// resumeArgs is the half of a tool's input that carries the host's answer to the outstanding
// host call: the session to resume, and exactly one of a signature, a response body, or the
// error the host hit producing either.
type resumeArgs struct {
	Session   string `json:"session"`
	Signature string `json:"signature"`  // base64 of the raw signature
	SignError string `json:"signError"`  // the host could not sign
	Response  string `json:"response"`   // base64 of the fetch response body
	FetchErr  string `json:"fetchError"` // the host could not send
}

// reply turns the host's answer into the HostReply the lifecycle is waiting for. An error from
// the host is delivered INTO the lifecycle rather than returned to the caller, so the engine's
// own failure path runs: a mint that cannot sign or cannot reach the network still unwinds
// (revoking anything it already created) instead of being cut off mid-flight.
func (a resumeArgs) reply() (token.HostReply, error) {
	switch {
	case a.SignError != "":
		return token.HostReply{Err: errors.New(a.SignError)}, nil
	case a.FetchErr != "":
		return token.HostReply{Err: errors.New(a.FetchErr)}, nil
	case a.Response != "":
		body, err := base64.StdEncoding.DecodeString(a.Response)
		if err != nil {
			return token.HostReply{}, fmt.Errorf("bad response: %w", err)
		}
		return token.HostReply{Body: body}, nil
	default:
		sig, err := token.ParseSignatureBytes(a.Signature)
		if err != nil {
			return token.HostReply{}, fmt.Errorf("bad signature: %w", err)
		}
		return token.HostReply{Signature: sig}, nil
	}
}

// pendingReply renders the session's outstanding host call as the tool's JSON reply: the bytes
// the host must sign, or the request body it must send. The host reads only these opaque bytes;
// it never learns what they mean, and it is never told where to send them (it holds the
// endpoint itself).
func pendingReply(id string, call token.HostCall) (string, error) {
	switch {
	case call.Sign != nil:
		return marshal(map[string]any{
			"session": id,
			"sign":    map[string]string{"message": base64.StdEncoding.EncodeToString(call.Sign.Message)},
		})
	case call.Fetch != nil:
		return marshal(map[string]any{
			"session": id,
			"fetch":   map[string]string{"body": base64.StdEncoding.EncodeToString(call.Fetch.Body)},
		})
	default:
		return "", fmt.Errorf("session %q parked on an empty host call", id)
	}
}

// verifyService hosts token_verify: a read-only report of a mint's scam-relevant state. It needs
// no key, but it does need the network, so it is a session like a mint: each RPC read crosses
// back to the host to be sent.
type verifyService struct {
	reg *sessionRegistry[token.VerifySession]
}

func newVerifyService() *verifyService {
	return &verifyService{reg: newRegistry[token.VerifySession]("verify-")}
}

func (v *verifyService) tool() mcpserver.Tool {
	return mcpserver.Tool{
		Name: "token_verify",
		Description: "Verify a Solana mint: report supply, decimals, and whether the mint and freeze authorities " +
			"are revoked (a safe token has both revoked). The chain is read through the host, which holds the RPC " +
			"endpoint, so the call completes through the host's fetch loop.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"mint":{"type":"string"}}}`),
		Handler:     v.handle,
	}
}

func (v *verifyService) handle(_ context.Context, arguments json.RawMessage) (string, error) {
	var a struct {
		resumeArgs
		Mint string `json:"mint"`
	}
	if err := json.Unmarshal(arguments, &a); err != nil {
		return "", fmt.Errorf("token_verify: bad input: %w", err)
	}

	if a.Session == "" {
		pk, err := token.ParsePubkey(a.Mint)
		if err != nil {
			return "", fmt.Errorf("token_verify: bad mint address: %w", err)
		}
		s := token.StartVerify(pk)
		return v.render(v.reg.store(s), s)
	}

	s := v.reg.get(a.Session)
	if s == nil {
		return "", fmt.Errorf("token_verify: unknown session %q", a.Session)
	}
	r, err := a.reply()
	if err != nil {
		return "", fmt.Errorf("token_verify: %w", err)
	}
	if err := s.Advance(r); err != nil {
		v.reg.remove(a.Session)
		return "", fmt.Errorf("token_verify: %w", err)
	}
	return v.render(a.Session, s)
}

// render turns the verify session's current state into the tool's JSON reply: the next host call,
// or the final report. A Token-2022 mint is reported as its own UNSAFE class rather than a read
// failure, because it can carry transfer hooks, fees, or a permanent delegate.
func (v *verifyService) render(id string, s *token.VerifySession) (string, error) {
	if out, done := s.Result(); done {
		v.reg.remove(id)
		if out.Err != nil {
			if errors.Is(out.Err, token.ErrToken2022Mint) {
				return fmt.Sprintf("mint %s: UNSAFE - Token-2022 mint that may carry transfer hooks, transfer fees, "+
					"or a permanent delegate; not a plain fixed-supply SPL mint", out.State.Mint), nil
			}
			return "", out.Err
		}
		st := out.State
		return fmt.Sprintf("mint %s: supply=%d decimals=%d mintAuthorityRevoked=%t freezeAbsent=%t",
			st.Mint, st.Supply, st.Decimals, st.SupplyFixed(), !st.Freezable()), nil
	}
	call, ok := s.Pending()
	if !ok {
		return "", fmt.Errorf("token_verify: session %q is neither done nor awaiting the host", id)
	}
	return pendingReply(id, call)
}

// mintService hosts token_mint. A mint is a resumable session: the payer key lives in the flynn
// vault and the RPC endpoint lives with the host, so the tool cannot complete a mint in one call.
// The first call starts a session and returns the first thing the host must do; each later call
// delivers the host's answer and returns the next host call or the final outcome.
type mintService struct {
	reg *sessionRegistry[token.Session]
	// opts configure each session this service starts. Production passes none, so a mint polls
	// for confirmation on the system clock; a test passes its own clock so it does not sleep in
	// real time while driving the choreography.
	opts []token.MintOption
}

func newMintService(opts ...token.MintOption) *mintService {
	return &mintService{reg: newRegistry[token.Session]("mint-"), opts: opts}
}

func (m *mintService) tool() mcpserver.Tool {
	return mcpserver.Tool{
		Name: "token_mint",
		Description: "Mint a new fixed-supply SPL token safely on Solana: create the mint, attach metadata, " +
			"mint the whole supply, then revoke the mint authority (freeze authority is never set). A scam-shaped " +
			"request is refused. Call it with {name,symbol,metadataUri,decimals,supply}; the transactions are signed " +
			"by the host with a key this tool never holds and submitted through the host's RPC endpoint, so the call " +
			"completes through the host's call loop and returns {done,mint}.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{` +
			`"name":{"type":"string"},"symbol":{"type":"string"},"metadataUri":{"type":"string"},` +
			`"decimals":{"type":"integer"},"supply":{"type":"integer"}}}`),
		Handler: m.handle,
	}
}

func (m *mintService) handle(_ context.Context, arguments json.RawMessage) (string, error) {
	var a struct {
		resumeArgs
		HostKey     string          `json:"_hostKey"` // base64 of the host signing key's public bytes
		Name        string          `json:"name"`
		Symbol      string          `json:"symbol"`
		MetadataURI string          `json:"metadataUri"`
		Decimals    uint8           `json:"decimals"`
		Supply      json.RawMessage `json:"supply"`
	}
	a.Decimals = 9
	if err := json.Unmarshal(arguments, &a); err != nil {
		return "", fmt.Errorf("token_mint: bad input: %w", err)
	}

	if a.Session == "" {
		// The payer is the host's signing key, injected as its public bytes on the first call.
		// This extension never holds the key; it only builds against the public half and hands
		// each transaction back to the host to sign.
		payer, err := token.ParsePubkeyBytes(a.HostKey)
		if err != nil {
			return "", fmt.Errorf("token_mint: bad host key: %w", err)
		}
		supply, err := parseSupply(a.Supply)
		if err != nil {
			return "", fmt.Errorf("token_mint: %w", err)
		}
		s := token.StartMint(payer, token.MintSpec{
			Name: a.Name, Symbol: a.Symbol, MetadataURI: a.MetadataURI, Decimals: a.Decimals, Supply: supply,
		}, m.opts...)
		return m.render(m.reg.store(s), s)
	}

	s := m.reg.get(a.Session)
	if s == nil {
		return "", fmt.Errorf("token_mint: unknown session %q", a.Session)
	}
	r, err := a.reply()
	if err != nil {
		return "", fmt.Errorf("token_mint: %w", err)
	}
	if err := s.Advance(r); err != nil {
		m.reg.remove(a.Session)
		return "", fmt.Errorf("token_mint: %w", err)
	}
	return m.render(a.Session, s)
}

// render turns the mint session's current state into the tool's JSON reply: the next host call,
// or the final outcome. A completed session is dropped from the registry.
func (m *mintService) render(id string, s *token.Session) (string, error) {
	if out, done := s.Result(); done {
		m.reg.remove(id)
		resp := map[string]any{"done": true, "mint": out.Mint.String()}
		if out.Err != nil {
			resp["error"] = out.Err.Error()
		}
		if len(out.Disclosures) > 0 {
			ds := make([]map[string]string, 0, len(out.Disclosures))
			for _, d := range out.Disclosures {
				ds = append(ds, map[string]string{"code": d.Code, "detail": d.Detail})
			}
			resp["disclosures"] = ds
		}
		return marshal(resp)
	}
	call, ok := s.Pending()
	if !ok {
		return "", fmt.Errorf("token_mint: session %q is neither done nor awaiting the host", id)
	}
	return pendingReply(id, call)
}

func marshal(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("token: encode reply: %w", err)
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
