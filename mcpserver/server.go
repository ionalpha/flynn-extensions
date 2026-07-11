// Package mcpserver is the shared harness every flynn extension uses to expose its tools.
//
// A flynn extension is an out-of-process binary that speaks the Model Context Protocol over
// stdio: flynn launches it, connects as an MCP client, and mounts the tools it advertises
// (namespaced, capability-gated, governed at the dispatch waist on the flynn side). This
// package handles the JSON-RPC framing and the initialize/tools/list/tools/call methods, so
// an extension author writes only Tool handlers, not protocol.
//
// Transport is newline-delimited JSON-RPC 2.0 on stdin/stdout, as the MCP stdio transport
// specifies. Nothing is written to stdout except protocol messages: logs and diagnostics go
// to stderr, because a stray stdout write would corrupt the message stream.
package mcpserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// protocolVersion is the MCP revision this harness implements and reports at initialize.
const protocolVersion = "2024-11-05"

// maxMessageBytes bounds a single JSON-RPC message so a hostile or broken peer cannot force
// unbounded buffering. 16 MiB is far above any legitimate tool call.
const maxMessageBytes = 16 << 20

// Tool is one capability the extension exposes. Handler receives the raw JSON arguments the
// caller supplied (validated on the flynn side against InputSchema) and returns the result
// text, or an error that is reported to the caller as a tool error (not a transport error).
type Tool struct {
	Name        string
	Description string
	InputSchema json.RawMessage
	Handler     func(ctx context.Context, arguments json.RawMessage) (string, error)
}

// Server hosts a set of tools over the MCP stdio transport.
type Server struct {
	name    string
	version string
	order   []string
	tools   map[string]Tool
}

// New returns a server that identifies itself to the client with name and version.
func New(name, version string) *Server {
	return &Server{name: name, version: version, tools: map[string]Tool{}}
}

// Register adds a tool. A tool whose name is already registered replaces the earlier one,
// so a caller building the set programmatically gets last-write-wins rather than a duplicate.
func (s *Server) Register(t Tool) {
	if _, ok := s.tools[t.Name]; !ok {
		s.order = append(s.order, t.Name)
	}
	s.tools[t.Name] = t
}

// jsonRPCRequest is an incoming JSON-RPC message. A request carries an id; a notification
// omits it, so a nil id marks a message that must not be answered.
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// JSON-RPC error codes used by this harness.
const (
	codeParseError    = -32700
	codeInvalidReq    = -32600
	codeMethodMissing = -32601
	codeInvalidParams = -32602
)

// Serve reads JSON-RPC messages from r and writes responses to w until r reaches EOF or the
// context is cancelled. It is the extension binary's main loop: call it with os.Stdin and
// os.Stdout. Errors from individual messages are reported back over the protocol; Serve
// itself returns only on a transport-level read failure.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxMessageBytes)
	for sc.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		resp, answer := s.dispatch(ctx, line)
		if !answer {
			continue
		}
		if err := writeMessage(w, resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

// dispatch parses one message and produces its response. The second result is false for a
// notification, which JSON-RPC forbids answering.
func (s *Server) dispatch(ctx context.Context, line []byte) (jsonRPCResponse, bool) {
	var req jsonRPCRequest
	if err := json.Unmarshal(line, &req); err != nil {
		return errorResponse(nil, codeParseError, "parse error"), true
	}
	notification := len(req.ID) == 0
	if req.JSONRPC != "2.0" {
		if notification {
			return jsonRPCResponse{}, false
		}
		return errorResponse(req.ID, codeInvalidReq, "jsonrpc must be \"2.0\""), true
	}

	switch req.Method {
	case "initialize":
		return s.resultResponse(req.ID, s.initializeResult()), true
	case "tools/list":
		return s.resultResponse(req.ID, s.listResult()), true
	case "tools/call":
		return s.callResult(ctx, req.ID, req.Params)
	case "ping":
		return s.resultResponse(req.ID, map[string]any{}), true
	case "notifications/initialized", "notifications/cancelled":
		// Client lifecycle notifications: acknowledged by doing nothing, never answered.
		return jsonRPCResponse{}, false
	default:
		if notification {
			return jsonRPCResponse{}, false
		}
		return errorResponse(req.ID, codeMethodMissing, "unknown method: "+req.Method), true
	}
}

func (s *Server) initializeResult() map[string]any {
	return map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]any{"name": s.name, "version": s.version},
	}
}

func (s *Server) listResult() map[string]any {
	list := make([]map[string]any, 0, len(s.order))
	for _, name := range s.order {
		t := s.tools[name]
		schema := t.InputSchema
		if len(schema) == 0 {
			schema = json.RawMessage(`{"type":"object"}`)
		}
		list = append(list, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": schema,
		})
	}
	return map[string]any{"tools": list}
}

// callResult runs a tools/call. A handler error is returned as an MCP tool error (a normal
// result with isError set), not a JSON-RPC transport error, so the model sees the failure
// as tool output it can react to.
func (s *Server) callResult(ctx context.Context, id, params json.RawMessage) (jsonRPCResponse, bool) {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil {
		return errorResponse(id, codeInvalidParams, "invalid tools/call params"), true
	}
	tool, ok := s.tools[call.Name]
	if !ok {
		return errorResponse(id, codeInvalidParams, "unknown tool: "+call.Name), true
	}
	out, err := tool.Handler(ctx, call.Arguments)
	if err != nil {
		return s.resultResponse(id, toolContent(err.Error(), true)), true
	}
	return s.resultResponse(id, toolContent(out, false)), true
}

func toolContent(text string, isError bool) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isError,
	}
}

func (s *Server) resultResponse(id json.RawMessage, result any) jsonRPCResponse {
	return jsonRPCResponse{JSONRPC: "2.0", ID: idOrNull(id), Result: result}
}

func errorResponse(id json.RawMessage, code int, msg string) jsonRPCResponse {
	return jsonRPCResponse{JSONRPC: "2.0", ID: idOrNull(id), Error: &jsonRPCError{Code: code, Message: msg}}
}

// idOrNull returns id, or a JSON null when it is absent, so a response always carries the
// id member JSON-RPC requires even when reporting a parse error on an unidentifiable message.
func idOrNull(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

// writeMessage serialises one response as a single newline-delimited line, the framing the
// MCP stdio transport uses.
func writeMessage(w io.Writer, resp jsonRPCResponse) error {
	b, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal response: %w", err)
	}
	b = append(b, '\n')
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	return nil
}
