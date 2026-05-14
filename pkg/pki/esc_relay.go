package pki

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ifEnforceEncryptICertRequest is the CA flag bit for IF_ENFORCEENCRYPTICERTREQUEST.
// When NOT set on the CA's flags attribute, the RPC interface does not enforce encryption,
// making the CA vulnerable to ESC11 (NTLM relay to RPC enrollment).
const ifEnforceEncryptICertRequest uint32 = 0x200

// EnrollmentService represents an AD CS enrollment service object from LDAP.
type EnrollmentService struct {
	Name           string   `json:"name"`
	DN             string   `json:"dn"`
	DNSHostName    string   `json:"dns_hostname"`
	Templates      []string `json:"templates"`
	Flags          uint32   `json:"flags"`
	EnrollmentURLs []string `json:"enrollment_urls"`
}

// ESC8Finding represents a CA with an HTTP web enrollment endpoint vulnerable to NTLM relay.
type ESC8Finding struct {
	CAName       string   `json:"ca_name"`
	CAHostname   string   `json:"ca_hostname"`
	HTTPEndpoint string   `json:"http_endpoint"`
	NTLMEnabled  bool     `json:"ntlm_enabled"`
	Templates    []string `json:"templates"`
}

// ESC11Finding represents a CA whose RPC interface does not enforce encryption,
// allowing NTLM relay attacks against the ICertPassage interface.
type ESC11Finding struct {
	CAName             string `json:"ca_name"`
	CAHostname         string `json:"ca_hostname"`
	Flags              uint32 `json:"flags"`
	EnforcesEncryption bool   `json:"enforces_encryption"`
}

// buildEnrollmentServicesBaseDN returns the LDAP base DN for the Enrollment Services container.
func buildEnrollmentServicesBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	var dcParts []string
	for _, p := range parts {
		dcParts = append(dcParts, "DC="+p)
	}
	return "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration," + strings.Join(dcParts, ",")
}

// EnumerateEnrollmentServices queries LDAP for pKIEnrollmentService objects under the
// Enrollment Services container. These represent CAs that are configured for enrollment
// and are the targets for ESC8 (HTTP relay) and ESC11 (RPC relay) attacks.
func EnumerateEnrollmentServices(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn) ([]EnrollmentService, error) {
	baseDN := buildEnrollmentServicesBaseDN(cfg.Domain)
	filter := "(objectClass=pKIEnrollmentService)"
	attrs := []string{
		"cn",
		"distinguishedName",
		"dNSHostName",
		"certificateTemplates",
		"flags",
		"msPKI-Enrollment-Servers",
	}

	fmt.Printf("[*] LDAP search: base=%s filter=%s\n", baseDN, filter)

	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attrs, nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	var services []EnrollmentService
	for _, entry := range result.Entries {
		svc := EnrollmentService{
			Name:        entry.GetAttributeValue("cn"),
			DN:          entry.GetAttributeValue("distinguishedName"),
			DNSHostName: entry.GetAttributeValue("dNSHostName"),
			Templates:   entry.GetAttributeValues("certificateTemplates"),
		}

		// Parse flags (integer stored as string or raw bytes)
		if v := entry.GetRawAttributeValue("flags"); len(v) >= 4 {
			svc.Flags = binary.LittleEndian.Uint32(v[:4])
		} else if vs := entry.GetAttributeValue("flags"); vs != "" {
			fmt.Sscanf(vs, "%d", &svc.Flags)
		}

		// msPKI-Enrollment-Servers is a multi-valued attribute containing enrollment URLs
		svc.EnrollmentURLs = entry.GetAttributeValues("msPKI-Enrollment-Servers")

		services = append(services, svc)
	}

	fmt.Printf("[+] Found %d enrollment service(s)\n", len(services))
	return services, nil
}

// ProbeWebEnrollment checks whether a CA hostname exposes the /certsrv/ web enrollment
// endpoint over HTTP or HTTPS, and whether NTLM authentication is enabled.
// ESC8 is exploitable when the endpoint is reachable over HTTP (port 80) with NTLM auth,
// because an attacker can relay coerced NTLM authentication to obtain a certificate.
func ProbeWebEnrollment(hostname string) (*ESC8Finding, error) {
	finding := &ESC8Finding{
		CAHostname: hostname,
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		// Do not follow redirects — we need to inspect the initial response
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // intentional: pen-test tool probing internal CA
			},
		},
	}

	// Probe HTTP first (the exploitable case for relay)
	httpURL := fmt.Sprintf("http://%s/certsrv/", hostname)
	if probeEndpoint(client, httpURL, finding) {
		return finding, nil
	}

	// Also check HTTPS — still worth noting even though relay is harder
	httpsURL := fmt.Sprintf("https://%s/certsrv/", hostname)
	if probeEndpoint(client, httpsURL, finding) {
		// HTTPS with NTLM is less exploitable but still worth flagging
		return finding, nil
	}

	return nil, fmt.Errorf("no web enrollment endpoint found on %s", hostname)
}

// probeEndpoint sends a GET to the URL and checks for NTLM auth indicators.
// Returns true if the endpoint is reachable and appears to support enrollment.
func probeEndpoint(client *http.Client, url string, finding *ESC8Finding) bool {
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// 401 with NTLM challenge = classic web enrollment with NTLM
	// 200 = web enrollment without auth (even worse)
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusOK {
		finding.HTTPEndpoint = url

		// Check WWW-Authenticate header for NTLM or Negotiate (which includes NTLM)
		for _, auth := range resp.Header.Values("WWW-Authenticate") {
			authUpper := strings.ToUpper(auth)
			if strings.Contains(authUpper, "NTLM") || strings.Contains(authUpper, "NEGOTIATE") {
				finding.NTLMEnabled = true
				break
			}
		}

		// 200 without auth is also exploitable (no auth required at all)
		if resp.StatusCode == http.StatusOK {
			finding.NTLMEnabled = true
		}

		return true
	}

	return false
}

// ScanESC8 enumerates enrollment services and probes each for HTTP web enrollment
// endpoints vulnerable to NTLM relay. Returns findings for CAs where the /certsrv/
// endpoint is reachable over HTTP with NTLM authentication enabled.
func ScanESC8(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn) ([]ESC8Finding, error) {
	fmt.Println("[*] Scanning for ESC8 (NTLM relay to AD CS HTTP endpoints)...")

	services, err := EnumerateEnrollmentServices(ctx, cfg, conn)
	if err != nil {
		return nil, fmt.Errorf("enumerate enrollment services: %w", err)
	}

	var findings []ESC8Finding
	for _, svc := range services {
		if svc.DNSHostName == "" {
			fmt.Printf("[!] Enrollment service %q has no dNSHostName, skipping probe\n", svc.Name)
			continue
		}

		stealthDelay(cfg)
		fmt.Printf("[*] Probing web enrollment on %s (%s)...\n", svc.Name, svc.DNSHostName)
		finding, err := ProbeWebEnrollment(svc.DNSHostName)
		if err != nil {
			fmt.Printf("[*] %s: no web enrollment endpoint found\n", svc.DNSHostName)
			continue
		}

		finding.CAName = svc.Name
		finding.Templates = svc.Templates

		if finding.NTLMEnabled {
			fmt.Printf("[!] ESC8 VULNERABLE: %s — %s (NTLM enabled)\n", svc.Name, finding.HTTPEndpoint)
		} else {
			fmt.Printf("[*] ESC8 PARTIAL: %s — %s (no NTLM in WWW-Authenticate)\n", svc.Name, finding.HTTPEndpoint)
		}

		findings = append(findings, *finding)
	}

	return findings, nil
}

// ESC12Finding represents a CA whose DCOM interface (ICertRequest) is remotely accessible,
// enabling abuse when the CA's private key is stored on a network HSM or when DCOM-based
// enrollment lacks proper access controls.
type ESC12Finding struct {
	CAName         string `json:"ca_name"`
	CAHostname     string `json:"ca_hostname"`
	DCOMAccessible bool   `json:"dcom_accessible"`
	Flags          uint32 `json:"flags"`
}

// ScanESC12 enumerates enrollment services and probes each CA for an accessible DCOM
// endpoint mapper (TCP port 135). When the DCOM endpoint is reachable, an attacker can
// invoke the ICertRequest DCOM interface to request certificates remotely — particularly
// dangerous when the CA's private key is stored on a network HSM, as the DCOM interface
// bypasses normal enrollment restrictions.
func ScanESC12(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn) ([]ESC12Finding, error) {
	fmt.Println("[*] Scanning for ESC12 (DCOM interface abuse on CA / network HSM key storage)...")

	services, err := EnumerateEnrollmentServices(ctx, cfg, conn)
	if err != nil {
		return nil, fmt.Errorf("enumerate enrollment services: %w", err)
	}

	var findings []ESC12Finding
	for _, svc := range services {
		if svc.DNSHostName == "" {
			fmt.Printf("[!] Enrollment service %q has no dNSHostName, skipping DCOM probe\n", svc.Name)
			continue
		}

		stealthDelay(cfg)
		fmt.Printf("[*] Probing DCOM endpoint mapper on %s (%s:135)...\n", svc.Name, svc.DNSHostName)

		dcomAccessible := probeDCOMEndpoint(svc.DNSHostName)

		if dcomAccessible {
			finding := ESC12Finding{
				CAName:         svc.Name,
				CAHostname:     svc.DNSHostName,
				DCOMAccessible: true,
				Flags:          svc.Flags,
			}
			fmt.Printf("[!] ESC12 VULNERABLE: %s — DCOM endpoint mapper reachable on %s:135 (flags=0x%08x)\n",
				svc.Name, svc.DNSHostName, svc.Flags)
			findings = append(findings, finding)
		} else {
			fmt.Printf("[+] ESC12 SAFE: %s — DCOM endpoint mapper not reachable on %s:135\n",
				svc.Name, svc.DNSHostName)
		}
	}

	return findings, nil
}

// probeDCOMEndpoint attempts a TCP connection to port 135 (DCOM endpoint mapper) on the
// given hostname. Returns true if the port is reachable within the timeout.
func probeDCOMEndpoint(hostname string) bool {
	conn, err := net.DialTimeout("tcp", hostname+":135", 5*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ScanESC11 enumerates enrollment services and checks the CA flags attribute for the
// IF_ENFORCEENCRYPTICERTREQUEST bit (0x200). When this flag is NOT set, the CA's RPC
// interface (ICertPassage) does not enforce encryption, making it vulnerable to NTLM
// relay attacks via the MS-ICPR protocol.
func ScanESC11(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn) ([]ESC11Finding, error) {
	fmt.Println("[*] Scanning for ESC11 (NTLM relay to AD CS RPC interface)...")

	services, err := EnumerateEnrollmentServices(ctx, cfg, conn)
	if err != nil {
		return nil, fmt.Errorf("enumerate enrollment services: %w", err)
	}

	var findings []ESC11Finding
	for _, svc := range services {
		enforces := (svc.Flags & ifEnforceEncryptICertRequest) != 0

		finding := ESC11Finding{
			CAName:             svc.Name,
			CAHostname:         svc.DNSHostName,
			Flags:              svc.Flags,
			EnforcesEncryption: enforces,
		}

		if !enforces {
			fmt.Printf("[!] ESC11 VULNERABLE: %s — IF_ENFORCEENCRYPTICERTREQUEST not set (flags=0x%08x)\n",
				svc.Name, svc.Flags)
		} else {
			fmt.Printf("[+] ESC11 SAFE: %s — encryption enforced (flags=0x%08x)\n", svc.Name, svc.Flags)
		}

		// Only include vulnerable CAs in findings
		if !enforces {
			findings = append(findings, finding)
		}
	}

	return findings, nil
}
