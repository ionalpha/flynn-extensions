// Command example is a minimal flynn extension: a template that shows the shape every
// extension follows. It registers one tool on the mcpserver harness and serves the MCP
// stdio transport. Run it directly and it speaks JSON-RPC on stdin/stdout; flynn launches it
// the same way and mounts its tools.
//
// A real extension replaces the tool set with its own and keeps everything else identical.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ionalpha/flynn-extensions/mcpserver"
)

// version is stamped at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	s := mcpserver.New("example", version)
	s.Register(mcpserver.Tool{
		Name:        "example_echo",
		Description: "Echo the given text back. A placeholder demonstrating the extension shape.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}`),
		Handler: func(_ context.Context, arguments json.RawMessage) (string, error) {
			var a struct {
				Text string `json:"text"`
			}
			if err := json.Unmarshal(arguments, &a); err != nil {
				return "", fmt.Errorf("bad input: %w", err)
			}
			return "echo: " + a.Text, nil
		},
	})

	// Serve until stdin closes. Diagnostics go to stderr so they never corrupt the stdout
	// protocol stream.
	if err := s.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "example extension:", err)
		os.Exit(1)
	}
}
