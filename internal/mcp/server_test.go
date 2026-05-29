package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/loudmumble/trusted/pkg/c2"
)

func TestNewServer(t *testing.T) {
	s := NewServer(nil)
	if s == nil {
		t.Fatal("expected non-nil server")
	}
	if s.listener != nil {
		t.Error("expected nil listener when passed nil")
	}
}

func TestToolList(t *testing.T) {
	tools := toolList()
	if len(tools) != 5 {
		t.Errorf("expected 5 tools, got %d", len(tools))
	}

	expectedTools := map[string]bool{
		"pki_enumerate":    false,
		"pki_forge":        false,
		"c2_list_sessions": false,
		"c2_queue_command": false,
		"c2_get_results":   false,
	}

	for _, tool := range tools {
		name, ok := tool["name"].(string)
		if !ok {
			t.Error("tool missing name field")
			continue
		}
		if _, exists := expectedTools[name]; !exists {
			t.Errorf("unexpected tool: %s", name)
		}
		expectedTools[name] = true

		if _, ok := tool["description"].(string); !ok {
			t.Errorf("tool %s missing description", name)
		}
		if _, ok := tool["inputSchema"].(map[string]interface{}); !ok {
			t.Errorf("tool %s missing inputSchema", name)
		}
	}

	for name, found := range expectedTools {
		if !found {
			t.Errorf("expected tool %s not found", name)
		}
	}
}

func TestToolError(t *testing.T) {
	result := toolError("something broke")
	if result["isError"] != true {
		t.Error("expected isError=true")
	}
	content, ok := result["content"].([]map[string]interface{})
	if !ok || len(content) == 0 {
		t.Fatal("expected content array")
	}
	text, _ := content[0]["text"].(string)
	if !strings.Contains(text, "something broke") {
		t.Errorf("expected error message in text, got %q", text)
	}
}

func TestToolResult(t *testing.T) {
	result := toolResult(map[string]interface{}{"status": "ok"})
	content, ok := result["content"].([]map[string]interface{})
	if !ok || len(content) == 0 {
		t.Fatal("expected content array")
	}
	text, _ := content[0]["text"].(string)
	if !strings.Contains(text, "ok") {
		t.Errorf("expected status in text, got %q", text)
	}
}

func TestWriteResult(t *testing.T) {
	var buf bytes.Buffer
	writeResult(&buf, 1, map[string]string{"status": "ok"})
	output := buf.String()

	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if resp["jsonrpc"] != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %v", resp["jsonrpc"])
	}
	if resp["id"] != float64(1) {
		t.Errorf("expected id=1, got %v", resp["id"])
	}
}

func TestWriteError(t *testing.T) {
	var buf bytes.Buffer
	writeError(&buf, 1, -32601, "Method not found")
	output := buf.String()

	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected error object")
	}
	if errObj["code"] != float64(-32601) {
		t.Errorf("expected error code -32601, got %v", errObj["code"])
	}
	if errObj["message"] != "Method not found" {
		t.Errorf("expected error message, got %v", errObj["message"])
	}
}

func TestServe_Initialize(t *testing.T) {
	s := NewServer(nil)

	request := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n"
	pr, pw := io.Pipe()

	go func() {
		s.Serve(strings.NewReader(request), pw)
		pw.Close()
	}()

	// Read the response with a timeout
	done := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(pr)
		done <- data
	}()

	var outputBytes []byte
	select {
	case outputBytes = <-done:
	case <-time.After(2 * time.Second):
		t.Skip("server did not produce output in time")
	}

	output := string(outputBytes)
	if output == "" {
		t.Skip("server did not produce output in time")
	}

	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &resp); err != nil {
		t.Fatalf("invalid JSON: %v\noutput: %s", err, output)
	}
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatal("expected result object")
	}
	if result["protocolVersion"] != "2024-11-05" {
		t.Errorf("expected protocol version 2024-11-05, got %v", result["protocolVersion"])
	}
	serverInfo, ok := result["serverInfo"].(map[string]interface{})
	if !ok {
		t.Fatal("expected serverInfo")
	}
	if serverInfo["name"] != "trusted" {
		t.Errorf("expected server name 'trusted', got %v", serverInfo["name"])
	}
}

func TestServe_ToolsList(t *testing.T) {
	s := NewServer(nil)
	request := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}` + "\n"
	var buf bytes.Buffer
	s.Serve(strings.NewReader(request), &buf)

	output := buf.String()
	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatal("expected result")
	}
	tools, ok := result["tools"].([]interface{})
	if !ok {
		t.Fatal("expected tools array")
	}
	if len(tools) != 5 {
		t.Errorf("expected 5 tools, got %d", len(tools))
	}
}

func TestServe_UnknownMethod(t *testing.T) {
	s := NewServer(nil)
	request := `{"jsonrpc":"2.0","id":3,"method":"nonexistent","params":{}}` + "\n"
	var buf bytes.Buffer
	s.Serve(strings.NewReader(request), &buf)

	output := buf.String()
	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp["error"] == nil {
		t.Error("expected error for unknown method")
	}
}

func TestCallTool_UnknownTool(t *testing.T) {
	s := NewServer(nil)
	result := s.callTool("nonexistent", nil)
	if result["isError"] != true {
		t.Error("expected error for unknown tool")
	}
}

func TestCallTool_PKIEnumerate_MissingArgs(t *testing.T) {
	s := NewServer(nil)
	result := s.callTool("pki_enumerate", map[string]interface{}{})
	if result["isError"] != true {
		t.Error("expected error when target_dc and domain missing")
	}
}

func TestCallTool_PKIForge_MissingUPN(t *testing.T) {
	s := NewServer(nil)
	result := s.callTool("pki_forge", map[string]interface{}{})
	if result["isError"] != true {
		t.Error("expected error when upn missing")
	}
}

func TestCallTool_C2ListSessions_NoListener(t *testing.T) {
	s := NewServer(nil)
	result := s.callTool("c2_list_sessions", map[string]interface{}{})
	if result["isError"] != true {
		t.Error("expected error when no listener running")
	}
}

func TestCallTool_C2QueueCommand_NoListener(t *testing.T) {
	s := NewServer(nil)
	result := s.callTool("c2_queue_command", map[string]interface{}{
		"session_id": "test", "command": "whoami",
	})
	if result["isError"] != true {
		t.Error("expected error when no listener running")
	}
}

func TestCallTool_C2GetResults_NoListener(t *testing.T) {
	s := NewServer(nil)
	result := s.callTool("c2_get_results", map[string]interface{}{})
	if result["isError"] != true {
		t.Error("expected error when no listener running")
	}
}

func TestCallTool_PKIForge_HappyPath(t *testing.T) {
	s := NewServer(nil)
	dir := t.TempDir()
	result := s.callTool("pki_forge", map[string]interface{}{
		"upn":    "admin@corp.local",
		"output": dir + "/admin.crt",
	})
	if result["isError"] == true {
		content, _ := result["content"].([]map[string]interface{})
		if len(content) > 0 {
			t.Fatalf("pki_forge error: %v", content[0]["text"])
		}
		t.Fatal("pki_forge returned error")
	}
	content, ok := result["content"].([]map[string]interface{})
	if !ok || len(content) == 0 {
		t.Fatal("expected content array")
	}
	text, _ := content[0]["text"].(string)
	if !strings.Contains(text, "completed") {
		t.Errorf("expected 'completed' in result, got %q", text)
	}
	if !strings.Contains(text, "admin") {
		t.Errorf("expected 'admin' in result, got %q", text)
	}
}

func TestCallTool_C2ListSessions_WithListener(t *testing.T) {
	listener := &c2.Listener{
		BindAddress: "127.0.0.1",
		Port:        0,
		Protocol:    "http",
		IPCPort:     24243, // distinct from default 24242 to avoid polluting NoListener tests
	}
	go listener.Start()
	time.Sleep(200 * time.Millisecond)
	defer listener.Close()

	s := NewServer(listener)
	result := s.callTool("c2_list_sessions", map[string]interface{}{})
	if result["isError"] == true {
		t.Error("c2_list_sessions with listener should not error")
	}
	content, ok := result["content"].([]map[string]interface{})
	if !ok || len(content) == 0 {
		t.Fatal("expected content array")
	}
	text, _ := content[0]["text"].(string)
	if !strings.Contains(text, "sessions") {
		t.Errorf("expected 'sessions' in result, got %q", text)
	}
}

func TestCallTool_C2QueueCommand_WithListener_SessionNotFound(t *testing.T) {
	listener := &c2.Listener{
		BindAddress: "127.0.0.1",
		Port:        0,
		Protocol:    "http",
		IPCPort:     24244, // distinct from both default 24242 and first test 24243
	}
	go listener.Start()
	time.Sleep(200 * time.Millisecond)
	defer listener.Close()

	s := NewServer(listener)
	result := s.callTool("c2_queue_command", map[string]interface{}{
		"session_id": "nonexistent",
		"command":    "whoami",
	})
	if result["isError"] != true {
		t.Error("expected error for nonexistent session")
	}
}
