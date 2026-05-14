package c2

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunAgent_InvalidConfig(t *testing.T) {
	err := RunAgent("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestRunAgent_MissingC2URL(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	cfg := AgentConfig{}
	data, _ := json.Marshal(cfg)
	os.WriteFile(cfgPath, data, 0600)

	err := RunAgent(cfgPath)
	if err == nil {
		t.Fatal("expected error for missing c2_url")
	}
}

func TestRunAgent_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte("{invalid"), 0600)

	err := RunAgent(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestJitterRange(t *testing.T) {
	interval := 5
	jitter := 20

	for i := 0; i < 100; i++ {
		jitterMS := rand.Intn(interval * jitter * 10)
		jitterDuration := time.Duration(jitterMS) * time.Millisecond

		if jitterDuration < 0 || jitterDuration > time.Duration(interval)*time.Second {
			t.Errorf("jitter %v out of expected range [0, %ds]", jitterDuration, interval)
		}
	}
}

func TestAgentIntegration(t *testing.T) {
	// Find a free port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	// Start listener
	listener := &Listener{
		BindAddress: "127.0.0.1",
		Port:        port,
		Protocol:    "http",
	}

	go listener.Start()
	time.Sleep(200 * time.Millisecond)

	// Write agent config
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "stager.json")
	cfg := AgentConfig{
		StagerConfig: StagerConfig{
			C2URL:    fmt.Sprintf("http://127.0.0.1:%d", port),
			Interval: 1,
			Jitter:   10,
		},
	}
	data, _ := json.Marshal(cfg)
	os.WriteFile(cfgPath, data, 0600)

	// Run agent in background, let it do 2 poll cycles
	done := make(chan error, 1)
	go func() {
		done <- RunAgent(cfgPath)
	}()

	// Wait for agent to register
	time.Sleep(1500 * time.Millisecond)

	// Verify session registered
	sessions := listener.ListSessions()
	if len(sessions) == 0 {
		t.Fatal("expected at least 1 session after agent checkin")
	}

	sess := sessions[0]
	if sess.Hostname == "" {
		t.Error("session hostname should not be empty")
	}
	if sess.OS == "" {
		t.Error("session OS should not be empty")
	}

	// Queue a command
	cmdID, err := listener.QueueCommand(sess.ID, "echo", "trusted-test")
	if err != nil {
		t.Fatalf("queue command: %v", err)
	}
	if cmdID == "" {
		t.Fatal("command ID should not be empty")
	}

	// Wait for agent to pick up and execute
	time.Sleep(2 * time.Second)

	// Verify result
	results := listener.GetResults(sess.ID)
	if len(results) == 0 {
		t.Fatal("expected command result after execution")
	}

	found := false
	for _, r := range results {
		if r.CommandID == cmdID {
			found = true
			if r.ExitCode != 0 {
				t.Errorf("expected exit code 0, got %d", r.ExitCode)
			}
			if r.Output != "trusted-test" {
				t.Errorf("expected output 'trusted-test', got %q", r.Output)
			}
		}
	}
	if !found {
		t.Errorf("result for command %s not found", cmdID)
	}
}
