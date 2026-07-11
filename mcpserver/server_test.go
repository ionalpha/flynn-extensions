package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// run feeds newline-delimited requests through Serve and returns the decoded response lines.
func run(t *testing.T, s *Server, requests ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := s.Serve(context.Background(), strings.NewReader(strings.Join(requests, "\n")+"\n"), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var responses []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("decode response %q: %v", line, err)
		}
		responses = append(responses, m)
	}
	return responses
}

func echoServer() *Server {
	s := New("test", "0.0.1")
	s.Register(Tool{
		Name:        "echo",
		Description: "echoes its text",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}`),
		Handler: func(_ context.Context, args json.RawMessage) (string, error) {
			var a struct {
				Text string `json:"text"`
			}
			if err := json.Unmarshal(args, &a); err != nil {
				return "", err
			}
			return "echo: " + a.Text, nil
		},
	})
	return s
}

func TestInitializeReportsProtocolAndTools(t *testing.T) {
	resp := run(t, echoServer(), `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if len(resp) != 1 {
		t.Fatalf("expected 1 response, got %d", len(resp))
	}
	result, ok := resp[0]["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result object: %v", resp[0])
	}
	if result["protocolVersion"] != protocolVersion {
		t.Fatalf("protocolVersion = %v, want %s", result["protocolVersion"], protocolVersion)
	}
	if _, ok := result["capabilities"].(map[string]any)["tools"]; !ok {
		t.Fatal("initialize did not advertise the tools capability")
	}
}

func TestToolsListAdvertisesRegisteredTools(t *testing.T) {
	resp := run(t, echoServer(), `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	tools := resp[0]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	if tools[0].(map[string]any)["name"] != "echo" {
		t.Fatalf("tool name = %v, want echo", tools[0].(map[string]any)["name"])
	}
}

func TestToolsCallInvokesHandler(t *testing.T) {
	resp := run(t, echoServer(), `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`)
	result := resp[0]["result"].(map[string]any)
	if result["isError"] != false {
		t.Fatalf("isError = %v, want false", result["isError"])
	}
	text := result["content"].([]any)[0].(map[string]any)["text"]
	if text != "echo: hi" {
		t.Fatalf("text = %v, want 'echo: hi'", text)
	}
}

func TestHandlerErrorIsAToolErrorNotTransportError(t *testing.T) {
	// Bad arguments make the handler return an error; MCP reports that as isError:true tool
	// output, NOT a JSON-RPC error, so the model can react to it.
	resp := run(t, echoServer(), `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":"not-an-object"}}`)
	if _, isTransportError := resp[0]["error"]; isTransportError {
		t.Fatalf("handler failure surfaced as a transport error: %v", resp[0])
	}
	if resp[0]["result"].(map[string]any)["isError"] != true {
		t.Fatalf("expected isError=true, got %v", resp[0]["result"])
	}
}

func TestUnknownToolIsRejected(t *testing.T) {
	resp := run(t, echoServer(), `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope","arguments":{}}}`)
	if _, ok := resp[0]["error"]; !ok {
		t.Fatalf("calling an unknown tool should be a params error, got %v", resp[0])
	}
}

func TestUnknownMethodReturnsMethodNotFound(t *testing.T) {
	resp := run(t, echoServer(), `{"jsonrpc":"2.0","id":6,"method":"does/notexist"}`)
	errObj, ok := resp[0]["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected an error, got %v", resp[0])
	}
	if errObj["code"].(float64) != codeMethodMissing {
		t.Fatalf("code = %v, want %d", errObj["code"], codeMethodMissing)
	}
}

func TestNotificationIsNotAnswered(t *testing.T) {
	// A notification (no id) must never get a response, even for an unknown method.
	resp := run(t, echoServer(),
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"some/notification"}`,
		`{"jsonrpc":"2.0","id":7,"method":"ping"}`,
	)
	if len(resp) != 1 {
		t.Fatalf("expected only the ping to be answered, got %d responses", len(resp))
	}
	if resp[0]["id"].(float64) != 7 {
		t.Fatalf("answered the wrong message: %v", resp[0])
	}
}

func TestParseErrorReportsNullID(t *testing.T) {
	resp := run(t, echoServer(), `{not valid json`)
	if resp[0]["id"] != nil {
		t.Fatalf("parse error id = %v, want null", resp[0]["id"])
	}
	if resp[0]["error"].(map[string]any)["code"].(float64) != codeParseError {
		t.Fatalf("expected parse-error code, got %v", resp[0]["error"])
	}
}

func TestRegisterReplacesByName(t *testing.T) {
	s := New("t", "0")
	s.Register(Tool{Name: "x", Description: "first"})
	s.Register(Tool{Name: "x", Description: "second"})
	resp := run(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	tools := resp[0]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["description"] != "second" {
		t.Fatalf("expected one tool with the replacement description, got %v", tools)
	}
}
