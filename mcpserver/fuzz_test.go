package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// FuzzDispatch throws arbitrary bytes at the JSON-RPC request handler. The server reads these
// off stdin, and stdin is written by whatever launched the extension, so a malformed or hostile
// line must never crash the process: a panic here is a denial of service on the tool-server
// triggered by its input. The property is total and simple: dispatch either produces a
// response or classifies the line as a notification, and never panics, for every input.
func FuzzDispatch(f *testing.F) {
	for _, s := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`,
		`{`, ``, `null`, `[]`, `{"jsonrpc":"1.0"}`, `{"id":1}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`,
	} {
		f.Add([]byte(s))
	}

	s := New("fuzz", "0")
	s.Register(Tool{
		Name: "echo", Description: "d",
		InputSchema: []byte(`{"type":"object"}`),
		Handler:     func(context.Context, json.RawMessage) (string, error) { return "ok", nil },
	})
	f.Fuzz(func(_ *testing.T, line []byte) {
		// A newline inside the input would split into multiple lines through the real reader;
		// dispatch takes one line, so strip newlines to keep the target on a single message.
		line = bytes.ReplaceAll(line, []byte("\n"), nil)
		_, _ = s.dispatch(context.Background(), line) // must never panic
	})
}

// FuzzServeStream drives the full stdio loop over arbitrary multi-line input, so the framing
// (the scanner, the notification handling, the response writing) is exercised as a whole. It
// must always terminate and never panic whatever the stream contains.
func FuzzServeStream(f *testing.F) {
	f.Add("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n")
	f.Add("garbage\n{\"jsonrpc\":\"2.0\"}\n\n")
	f.Add("")

	srv := New("fuzz", "0")
	f.Fuzz(func(_ *testing.T, stream string) {
		var out bytes.Buffer
		// A bounded reader: the loop reads until EOF, and the input is finite, so it returns.
		_ = srv.Serve(context.Background(), strings.NewReader(stream), &out)
	})
}
