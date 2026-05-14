package pki

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// CertTemplate represents an ADCS certificate template with security-relevant attributes.
type CertTemplate struct {
	Name                    string        `json:"name"`
	DisplayName             string        `json:"display_name"`
	DN                      string        `json:"dn"`
	OID                     string        `json:"oid"`
	SchemaVersion           int           `json:"schema_version"`
	EnrollmentFlag          uint32        `json:"enrollment_flag"`
	NameFlag                uint32        `json:"name_flag"`
	CertificateNameFlag     uint32        `json:"certificate_name_flag"`
	EKUs                    []string      `json:"ekus"`
	AuthenticationEKU       bool          `json:"authentication_eku"`
	EnrolleeSuppliesSubject bool          `json:"enrollee_supplies_subject"`
	RequiresManagerApproval bool          `json:"requires_manager_approval"`
	AuthorizedSignatures    int           `json:"authorized_signatures"`
	SecurityDescriptor      []byte        `json:"security_descriptor,omitempty"`
	IssuancePolicyOIDs      []string      `json:"issuance_policy_oids,omitempty"`
	ESCVulns                []string      `json:"esc_vulns,omitempty"`
	ESCScore                int           `json:"esc_score"`
	ESC4Findings            []ESC4Finding `json:"esc4_findings,omitempty"`
}

// ESC flags and constants
const (
	// msPKI-Certificate-Name-Flag: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
	ctFlagEnrolleeSuppliesSubject uint32 = 0x00000001
	// msPKI-Enrollment-Flag: CT_FLAG_PEND_ALL_REQUESTS (manager approval)
	ctFlagPendAllRequests uint32 = 0x00000002
	// Authentication EKUs
	ekuClientAuth       = "1.3.6.1.5.5.7.3.2"
	ekuPKINITClientAuth = "1.3.6.1.5.2.3.4"
	ekuSmartCardLogon   = "1.3.6.1.4.1.311.20.2.2"
	ekuAnyPurpose       = "2.5.29.37.0"
)

// EnumerateTemplates queries ADCS for full template details via native LDAP.
func EnumerateTemplates(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn) ([]CertTemplate, error) {
	baseDN := buildCertTemplateBaseDN(cfg.Domain)
	filter := "(objectClass=pKICertificateTemplate)"
	attrs := []string{
		"cn", "displayName", "distinguishedName",
		"msPKI-Cert-Template-OID",
		"msPKI-Certificate-Name-Flag",
		"msPKI-Enrollment-Flag",
		"msPKI-RA-Signature",
		"pKIExtendedKeyUsage",
		"msPKI-Certificate-Application-Policy",
		"revision",
		"msPKI-Template-Schema-Version",
		"nTSecurityDescriptor",
	}

	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attrs, nil,
	)

	var entries []*ldap.Entry
	if pageSize := stealthPageSize(cfg); pageSize > 0 {
		result, err := conn.SearchWithPaging(searchReq, uint32(pageSize))
		if err != nil {
			return nil, fmt.Errorf("LDAP paged search failed: %w", err)
		}
		entries = result.Entries
		stealthPageDelay(cfg)
	} else {
		result, err := conn.Search(searchReq)
		if err != nil {
			return nil, fmt.Errorf("LDAP search failed: %w", err)
		}
		entries = result.Entries
	}

	if len(entries) == 0 {
		fmt.Printf("[!] No certificate templates found in %s\n", baseDN)
		fmt.Printf("[!] This may indicate: (1) ADCS is not installed, (2) the account lacks read permissions,\n")
		fmt.Printf("    or (3) templates are in a non-standard location. Try using an account with GenericRead.\n")
		return []CertTemplate{}, nil
	}

	var templates []CertTemplate
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return templates, ctx.Err()
		default:
		}

		tmpl := CertTemplate{
			Name:        entry.GetAttributeValue("cn"),
			DisplayName: entry.GetAttributeValue("displayName"),
			DN:          entry.GetAttributeValue("distinguishedName"),
			OID:         entry.GetAttributeValue("msPKI-Cert-Template-OID"),
			EKUs:        entry.GetAttributeValues("pKIExtendedKeyUsage"),
		}

		// Parse numeric flags
		if v := entry.GetRawAttributeValue("msPKI-Certificate-Name-Flag"); len(v) >= 4 {
			tmpl.CertificateNameFlag = binary.LittleEndian.Uint32(v[:4])
		} else if vs := entry.GetAttributeValue("msPKI-Certificate-Name-Flag"); vs != "" {
			fmt.Sscanf(vs, "%d", &tmpl.CertificateNameFlag)
		}

		if v := entry.GetRawAttributeValue("msPKI-Enrollment-Flag"); len(v) >= 4 {
			tmpl.EnrollmentFlag = binary.LittleEndian.Uint32(v[:4])
		} else if vs := entry.GetAttributeValue("msPKI-Enrollment-Flag"); vs != "" {
			fmt.Sscanf(vs, "%d", &tmpl.EnrollmentFlag)
		}

		if vs := entry.GetAttributeValue("msPKI-RA-Signature"); vs != "" {
			fmt.Sscanf(vs, "%d", &tmpl.AuthorizedSignatures)
		}

		if vs := entry.GetAttributeValue("msPKI-Template-Schema-Version"); vs != "" {
			fmt.Sscanf(vs, "%d", &tmpl.SchemaVersion)
		}

		tmpl.IssuancePolicyOIDs = entry.GetAttributeValues("msPKI-Certificate-Application-Policy")
		tmpl.SecurityDescriptor = entry.GetRawAttributeValue("nTSecurityDescriptor")

		// Evaluate security properties
		tmpl.EnrolleeSuppliesSubject = (tmpl.CertificateNameFlag & ctFlagEnrolleeSuppliesSubject) != 0
		tmpl.RequiresManagerApproval = (tmpl.EnrollmentFlag & ctFlagPendAllRequests) != 0
		tmpl.AuthenticationEKU = hasAuthenticationEKU(tmpl.EKUs)

		// Score ESC vulnerabilities
		scoreESC(&tmpl)

		templates = append(templates, tmpl)

		stealthDelay(cfg)
	}

	return templates, nil
}

// hasAuthenticationEKU checks if the template has EKUs that allow authentication.
func hasAuthenticationEKU(ekus []string) bool {
	if len(ekus) == 0 {
		return true // No EKU restriction = any purpose
	}
	for _, eku := range ekus {
		switch eku {
		case ekuClientAuth, ekuPKINITClientAuth, ekuSmartCardLogon, ekuAnyPurpose:
			return true
		}
	}
	return false
}

// scoreESC evaluates a template for ESC1-ESC4 vulnerabilities and assigns a risk score.
func scoreESC(tmpl *CertTemplate) {
	tmpl.ESCVulns = nil
	tmpl.ESCScore = 0
	tmpl.ESC4Findings = nil

	// ESC1: Enrollee supplies subject + authentication EKU + no manager approval + no signatures
	if tmpl.EnrolleeSuppliesSubject && tmpl.AuthenticationEKU &&
		!tmpl.RequiresManagerApproval && tmpl.AuthorizedSignatures == 0 {
		tmpl.ESCVulns = append(tmpl.ESCVulns, "ESC1")
		tmpl.ESCScore += 10
	}

	// ESC2: Any Purpose EKU or no EKU restrictions + enrollee supplies subject
	hasAnyPurpose := false
	noEKUs := len(tmpl.EKUs) == 0
	for _, eku := range tmpl.EKUs {
		if eku == ekuAnyPurpose {
			hasAnyPurpose = true
		}
	}
	if (hasAnyPurpose || noEKUs) && tmpl.EnrolleeSuppliesSubject {
		tmpl.ESCVulns = append(tmpl.ESCVulns, "ESC2")
		tmpl.ESCScore += 8
	}

	// ESC3: Enrollment agent template (Certificate Request Agent EKU)
	for _, eku := range tmpl.EKUs {
		if eku == "1.3.6.1.4.1.311.20.2.1" { // Certificate Request Agent
			tmpl.ESCVulns = append(tmpl.ESCVulns, "ESC3")
			tmpl.ESCScore += 7
		}
	}

	// ESC4: WriteDacl/WriteOwner on template — full ACE parsing
	if len(tmpl.SecurityDescriptor) > 0 {
		findings, err := CheckESC4(tmpl.Name, tmpl.DN, tmpl.SecurityDescriptor)
		if err == nil && len(findings) > 0 {
			tmpl.ESC4Findings = findings
			tmpl.ESCVulns = append(tmpl.ESCVulns, "ESC4-EXPLOITABLE")
			tmpl.ESCScore += 6
		} else if len(tmpl.SecurityDescriptor) > 0 {
			tmpl.ESCVulns = append(tmpl.ESCVulns, "ESC4-CHECK")
			tmpl.ESCScore += 1
		}
	}

	// ESC9: CT_FLAG_NO_SECURITY_EXTENSION — no szOID_NTDS_CA_SECURITY_EXT extension
	if tmpl.EnrollmentFlag&0x00080000 != 0 && tmpl.AuthenticationEKU {
		tmpl.ESCVulns = append(tmpl.ESCVulns, "ESC9")
		tmpl.ESCScore += 6
	}

	// ESC5: Vulnerable PKI object ACLs
	for _, eku := range tmpl.EKUs {
		if eku == "1.3.6.1.4.1.311.20.2.1" && len(tmpl.SecurityDescriptor) > 0 {
			tmpl.ESCVulns = append(tmpl.ESCVulns, "ESC5-CHECK")
			tmpl.ESCScore += 5
		}
	}

	// ESC7: CA officers have ManageCA + ManageCertificates rights
	if tmpl.RequiresManagerApproval && len(tmpl.SecurityDescriptor) > 0 {
		tmpl.ESCVulns = append(tmpl.ESCVulns, "ESC7-CHECK")
		tmpl.ESCScore += 4
	}
}

// AutoDetectESC scans all templates and returns a prioritized list of exploitable paths.
func AutoDetectESC(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn) ([]CertTemplate, error) {
	templates, err := EnumerateTemplates(ctx, cfg, conn)
	if err != nil {
		return nil, err
	}

	var vulnerable []CertTemplate
	for _, t := range templates {
		if t.ESCScore > 0 {
			vulnerable = append(vulnerable, t)
		}
	}

	for i := 0; i < len(vulnerable)-1; i++ {
		for j := i + 1; j < len(vulnerable); j++ {
			if vulnerable[j].ESCScore > vulnerable[i].ESCScore {
				vulnerable[i], vulnerable[j] = vulnerable[j], vulnerable[i]
			}
		}
	}

	return vulnerable, nil
}
