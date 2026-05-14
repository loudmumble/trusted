package pki

import (
	"fmt"
	"strings"
	"time"
)

// Remediation advice keyed by ESC type.
var escRemediation = map[string]string{
	"ESC1":             "Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from template. Require manager approval. Restrict enrollment ACLs to specific security groups.",
	"ESC2":             "Remove Any Purpose EKU from the template. Replace with specific EKUs (e.g., Client Authentication only). Disable enrollee-supplies-subject.",
	"ESC3":             "Restrict enrollment in Certificate Request Agent templates to trusted operators only. Enable manager approval on enrollment agent templates.",
	"ESC4":             "Remove WriteDACL/WriteOwner ACEs for non-privileged trustees on the certificate template object. Audit template ACLs with certutil -v -dstemplate.",
	"ESC4-EXPLOITABLE": "CRITICAL: Remove WriteDACL/WriteOwner ACEs for non-privileged trustees immediately. An attacker can modify this template to enable ESC1.",
	"ESC4-CHECK":       "Audit the certificate template ACLs manually. Use certutil -v -dstemplate to inspect permissions.",
	"ESC5":             "Remove dangerous write ACEs (WriteDACL, WriteOwner, GenericAll, GenericWrite) from the CA LDAP object for non-privileged trustees. Audit CA permissions with certutil -v -ds.",
	"ESC5-CHECK":       "Audit the CA object ACLs. Check for overly permissive delegations on the CA's LDAP object.",
	"ESC6":             "Disable EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA: certutil -config \"CA\\Name\" -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2. Restart the CA service.",
	"ESC7":             "Remove ManageCA and ManageCertificates rights from non-administrative users. Audit CA officer roles.",
	"ESC7-CHECK":       "Audit CA officer roles and ManageCA/ManageCertificates assignments.",
	"ESC8":             "Disable HTTP-based enrollment (IIS certsrv). If web enrollment is required, enforce HTTPS-only with Extended Protection for Authentication (EPA). Disable NTLM on the web enrollment endpoint.",
	"ESC9":             "Remove CT_FLAG_NO_SECURITY_EXTENSION (0x00080000) from the template's msPKI-Enrollment-Flag. Set StrongCertificateBindingEnforcement to 2 (Full Enforcement) via registry or group policy.",
	"ESC11":            "Set IF_ENFORCEENCRYPTICERTREQUEST flag on the CA: certutil -config \"CA\\Name\" -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST. Restart the CA service.",
	"ESC13":            "Remove the msDS-OIDToGroupLink attribute from the issuance policy OID object, or restrict enrollment in the affected template to trusted users only.",
	"ESC10":            "Set CertificateMappingMethods registry value to 0x18 (disable UPN mapping and S4U2Self). Set StrongCertificateBindingEnforcement to 2 (Full Enforcement).",
	"ESC12":            "Restrict remote DCOM access to the CA server. If network HSM key storage is used, ensure DCOM enrollment interfaces are only accessible from authorized management hosts. Apply DCOM access control restrictions via Component Services (dcomcnfg).",
	"ESC14":            "Upgrade certificate templates to schema version 2 or higher. Set StrongCertificateBindingEnforcement to 2. Remove weak altSecurityIdentities mappings.",
}

// escSeverity maps ESC types to severity levels for reporting.
var escSeverity = map[string]string{
	"ESC1":             "CRITICAL",
	"ESC2":             "HIGH",
	"ESC3":             "HIGH",
	"ESC4":             "HIGH",
	"ESC4-EXPLOITABLE": "CRITICAL",
	"ESC4-CHECK":       "MEDIUM",
	"ESC5":             "CRITICAL",
	"ESC5-CHECK":       "MEDIUM",
	"ESC6":             "CRITICAL",
	"ESC7":             "HIGH",
	"ESC7-CHECK":       "MEDIUM",
	"ESC8":             "HIGH",
	"ESC9":             "HIGH",
	"ESC11":            "HIGH",
	"ESC13":            "HIGH",
	"ESC10":            "HIGH",
	"ESC12":            "HIGH",
	"ESC14":            "HIGH",
}

// GenerateReport produces an engagement report from enumeration results.
// Supported formats: "markdown". Returns the report as bytes.
func GenerateReport(result EnumerationResult, format string) ([]byte, error) {
	switch strings.ToLower(format) {
	case "markdown", "md":
		return generateMarkdownReport(result)
	default:
		return nil, fmt.Errorf("unsupported report format %q (supported: markdown)", format)
	}
}

func generateMarkdownReport(result EnumerationResult) ([]byte, error) {
	var b strings.Builder

	// Title
	b.WriteString("# Trusted ADCS Security Assessment Report\n\n")
	b.WriteString(fmt.Sprintf("**Generated:** %s  \n", time.Now().Format("2006-01-02 15:04:05 MST")))
	b.WriteString(fmt.Sprintf("**Domain:** %s  \n", result.Domain))
	b.WriteString(fmt.Sprintf("**Target DC:** %s  \n\n", result.TargetDC))

	// Executive Summary
	b.WriteString("## Executive Summary\n\n")

	critCount, highCount, medCount := countSeverities(result)
	totalFindings := critCount + highCount + medCount

	if totalFindings == 0 {
		b.WriteString("No exploitable ADCS misconfigurations were identified during this assessment.\n\n")
	} else {
		b.WriteString(fmt.Sprintf("Trusted identified **%d** finding(s) across the ADCS infrastructure:\n\n", totalFindings))
		b.WriteString(fmt.Sprintf("| Severity | Count |\n"))
		b.WriteString(fmt.Sprintf("|----------|-------|\n"))
		b.WriteString(fmt.Sprintf("| CRITICAL | %d |\n", critCount))
		b.WriteString(fmt.Sprintf("| HIGH     | %d |\n", highCount))
		b.WriteString(fmt.Sprintf("| MEDIUM   | %d |\n\n", medCount))

		b.WriteString(fmt.Sprintf("**Total templates enumerated:** %d  \n", len(result.Templates)))
		b.WriteString(fmt.Sprintf("**Aggregate risk score:** %d  \n\n", result.TotalScore))
	}

	// Template Findings
	vulnTemplates := 0
	for _, t := range result.Templates {
		if t.ESCScore > 0 {
			vulnTemplates++
		}
	}

	if vulnTemplates > 0 {
		b.WriteString("## Certificate Template Findings\n\n")
		b.WriteString("| Template | Vulnerabilities | Score | Enrollee Supplies Subject | Auth EKU | Manager Approval |\n")
		b.WriteString("|----------|----------------|-------|--------------------------|----------|------------------|\n")

		for _, t := range result.Templates {
			if t.ESCScore == 0 {
				continue
			}
			vulns := strings.Join(t.ESCVulns, ", ")
			b.WriteString(fmt.Sprintf("| %s | %s | %d | %v | %v | %v |\n",
				t.Name, vulns, t.ESCScore, t.EnrolleeSuppliesSubject, t.AuthenticationEKU, t.RequiresManagerApproval))
		}
		b.WriteString("\n")
	}

	// ESC4 detailed findings
	hasESC4 := false
	for _, t := range result.Templates {
		if len(t.ESC4Findings) > 0 {
			hasESC4 = true
			break
		}
	}
	if hasESC4 {
		b.WriteString("### ESC4 — Template ACL Findings\n\n")
		b.WriteString("| Template | Trustee (SID) | Rights | Access Mask |\n")
		b.WriteString("|----------|---------------|--------|-------------|\n")
		for _, t := range result.Templates {
			for _, f := range t.ESC4Findings {
				b.WriteString(fmt.Sprintf("| %s | %s | %s | 0x%08x |\n",
					t.Name, f.Trustee, strings.Join(f.Rights, ", "), f.AccessMask))
			}
		}
		b.WriteString("\n")
	}

	// ESC2 findings
	if len(result.ESC2Findings) > 0 {
		b.WriteString("### ESC2 — Any Purpose EKU Templates\n\n")
		b.WriteString("| Template | EKUs |\n")
		b.WriteString("|----------|------|\n")
		for _, f := range result.ESC2Findings {
			ekus := strings.Join(f.EKUs, ", ")
			b.WriteString(fmt.Sprintf("| %s | %s |\n", f.TemplateName, ekus))
		}
		b.WriteString("\n")
	}

	// ESC3 findings
	if len(result.ESC3Findings) > 0 {
		b.WriteString("### ESC3 — Enrollment Agent Templates\n\n")
		b.WriteString("| Template | Enrollment Agent EKU |\n")
		b.WriteString("|----------|----------------------|\n")
		for _, f := range result.ESC3Findings {
			b.WriteString(fmt.Sprintf("| %s | %v |\n", f.TemplateName, f.EnrollmentAgentEKU))
		}
		b.WriteString("\n")
	}

	// ESC5 findings
	if len(result.ESC5Findings) > 0 {
		b.WriteString("### ESC5 — CA Object ACL Findings\n\n")
		b.WriteString("| CA Name | CA DN | Trustee (SID) | Rights | Access Mask |\n")
		b.WriteString("|---------|-------|---------------|--------|-------------|\n")
		for _, f := range result.ESC5Findings {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | 0x%08x |\n",
				f.CAName, truncateDN(f.CADN, 60), f.Trustee, strings.Join(f.Rights, ", "), f.AccessMask))
		}
		b.WriteString("\n")
	}

	// ESC6 findings
	if len(result.ESC6Findings) > 0 {
		b.WriteString("### ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2\n\n")
		b.WriteString("| CA Name | Hostname | Flags |\n")
		b.WriteString("|---------|----------|-------|\n")
		for _, f := range result.ESC6Findings {
			b.WriteString(fmt.Sprintf("| %s | %s | 0x%08x |\n",
				f.CAName, f.CAHostname, f.Flags))
		}
		b.WriteString("\n")
	}

	// ESC7 findings
	if len(result.ESC7Findings) > 0 {
		b.WriteString("### ESC7 — Vulnerable CA ACLs\n\n")
		b.WriteString("| CA Name | CA DN | Trustee | ManageCA | ManageCerts | Access Mask |\n")
		b.WriteString("|---------|-------|---------|----------|-------------|-------------|\n")
		for _, f := range result.ESC7Findings {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %v | %v | 0x%08x |\n",
				f.CAName, truncateDN(f.CADN, 40), f.Trustee, f.ManageCA, f.ManageCertificates, f.AccessMask))
		}
		b.WriteString("\n")
	}

	// ESC8 findings
	if len(result.ESC8Findings) > 0 {
		b.WriteString("### ESC8 — Web Enrollment NTLM Relay\n\n")
		b.WriteString("| CA Name | Hostname | Endpoint | NTLM Enabled | Templates |\n")
		b.WriteString("|---------|----------|----------|--------------|----------|\n")
		for _, f := range result.ESC8Findings {
			tmpls := strings.Join(f.Templates, ", ")
			if len(tmpls) > 60 {
				tmpls = tmpls[:57] + "..."
			}
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %v | %s |\n",
				f.CAName, f.CAHostname, f.HTTPEndpoint, f.NTLMEnabled, tmpls))
		}
		b.WriteString("\n")
	}

	// ESC9 findings
	if len(result.ESC9Findings) > 0 {
		b.WriteString("### ESC9 — No Security Extension (UPN Spoofing)\n\n")
		b.WriteString("| Template | NO_SECURITY_EXTENSION | Auth EKU | Binding Enforcement |\n")
		b.WriteString("|----------|-----------------------|----------|---------------------|\n")
		for _, f := range result.ESC9Findings {
			enforcement := "Unknown"
			switch f.BindingEnforcement {
			case 0:
				enforcement = "Disabled (EXPLOITABLE)"
			case 1:
				enforcement = "Compatibility (EXPLOITABLE)"
			case 2:
				enforcement = "Full (mitigated)"
			}
			b.WriteString(fmt.Sprintf("| %s | %v | %v | %s |\n",
				f.TemplateName, f.HasNoSecurityExtension, f.AuthenticationEKU, enforcement))
		}
		b.WriteString("\n")
	}

	// ESC10 findings
	if len(result.ESC10Findings) > 0 {
		b.WriteString("### ESC10 — Weak Certificate Mapping\n\n")
		b.WriteString("| Mapping Methods | UPN Mapping | S4U2Self | Binding Enforcement | Vulnerable Templates |\n")
		b.WriteString("|-----------------|-------------|----------|---------------------|----------------------|\n")
		for _, f := range result.ESC10Findings {
			enforcement := "Unknown"
			switch f.BindingEnforcement {
			case 0:
				enforcement = "Disabled"
			case 1:
				enforcement = "Compatibility"
			case 2:
				enforcement = "Full"
			}
			tmpls := strings.Join(f.VulnerableTemplates, ", ")
			if len(tmpls) > 50 {
				tmpls = tmpls[:47] + "..."
			}
			b.WriteString(fmt.Sprintf("| 0x%02x | %v | %v | %s | %s |\n",
				f.MappingMethods, f.UPNMappingEnabled, f.S4U2SelfEnabled, enforcement, tmpls))
		}
		b.WriteString("\n")
	}

	// ESC11 findings
	if len(result.ESC11Findings) > 0 {
		b.WriteString("### ESC11 — RPC Interface NTLM Relay\n\n")
		b.WriteString("| CA Name | Hostname | Flags | Enforces Encryption |\n")
		b.WriteString("|---------|----------|-------|---------------------|\n")
		for _, f := range result.ESC11Findings {
			b.WriteString(fmt.Sprintf("| %s | %s | 0x%08x | %v |\n",
				f.CAName, f.CAHostname, f.Flags, f.EnforcesEncryption))
		}
		b.WriteString("\n")
	}

	// ESC12 findings
	if len(result.ESC12Findings) > 0 {
		b.WriteString("### ESC12 — DCOM Interface Abuse\n\n")
		b.WriteString("| CA Name | Hostname | DCOM Accessible | Flags |\n")
		b.WriteString("|---------|----------|-----------------|-------|\n")
		for _, f := range result.ESC12Findings {
			b.WriteString(fmt.Sprintf("| %s | %s | %v | 0x%08x |\n",
				f.CAName, f.CAHostname, f.DCOMAccessible, f.Flags))
		}
		b.WriteString("\n")
	}

	// ESC13 findings
	if len(result.ESC13Findings) > 0 {
		b.WriteString("### ESC13 — OID Group Link Abuse\n\n")
		b.WriteString("| Template | Issuance Policy OID | Linked Group | Group DN |\n")
		b.WriteString("|----------|---------------------|--------------|----------|\n")
		for _, f := range result.ESC13Findings {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
				f.TemplateName, f.IssuancePolicyOID, f.LinkedGroupName, truncateDN(f.LinkedGroup, 60)))
		}
		b.WriteString("\n")
	}

	// ESC14 findings
	if len(result.ESC14Findings) > 0 {
		b.WriteString("### ESC14 — Weak Explicit Mappings\n\n")
		b.WriteString("| Template | Schema Version | Explicit Mapping | Strong Mapping Required | Binding Enforcement |\n")
		b.WriteString("|----------|----------------|------------------|-------------------------|---------------------|\n")
		for _, f := range result.ESC14Findings {
			enforcement := "Unknown"
			switch f.BindingEnforcement {
			case 0:
				enforcement = "Disabled"
			case 1:
				enforcement = "Compatibility"
			case 2:
				enforcement = "Full"
			}
			b.WriteString(fmt.Sprintf("| %s | %d | %v | %v | %s |\n",
				f.TemplateName, f.SchemaVersion, f.AllowsExplicitMapping, f.StrongMappingRequired, enforcement))
		}
		b.WriteString("\n")
	}

	// Attack Path Diagrams
	b.WriteString("## Attack Path Diagrams\n\n")
	writeAttackPaths(&b, result)

	// Remediation
	b.WriteString("## Remediation Recommendations\n\n")
	writeRemediation(&b, result)

	// Appendix
	b.WriteString("## Appendix: All Enumerated Templates\n\n")
	b.WriteString("| # | Template Name | Schema Version | EKUs | Score |\n")
	b.WriteString("|---|--------------|----------------|------|-------|\n")
	for i, t := range result.Templates {
		ekus := strings.Join(t.EKUs, ", ")
		if ekus == "" {
			ekus = "(none — any purpose)"
		}
		if len(ekus) > 50 {
			ekus = ekus[:47] + "..."
		}
		b.WriteString(fmt.Sprintf("| %d | %s | %d | %s | %d |\n",
			i+1, t.Name, t.SchemaVersion, ekus, t.ESCScore))
	}
	b.WriteString("\n")

	b.WriteString("---\n")
	b.WriteString("*Report generated by Trusted — ADCS Attack Toolkit*\n")

	return []byte(b.String()), nil
}

// writeAttackPaths generates text-based attack path diagrams for each finding class.
func writeAttackPaths(b *strings.Builder, result EnumerationResult) {
	pathIndex := 0

	// ESC1 paths
	for _, t := range result.Templates {
		for _, v := range t.ESCVulns {
			if v != "ESC1" {
				continue
			}
			pathIndex++
			b.WriteString(fmt.Sprintf("### Path %d: ESC1 via `%s`\n\n", pathIndex, t.Name))
			b.WriteString("```\n")
			b.WriteString(fmt.Sprintf("  [Attacker] --(enroll with arbitrary SAN)--> [Template: %s]\n", t.Name))
			b.WriteString("      |\n")
			b.WriteString("      v\n")
			b.WriteString("  [CA issues cert with attacker-controlled UPN]\n")
			b.WriteString("      |\n")
			b.WriteString("      v\n")
			b.WriteString("  [Kerberos PKINIT / Schannel auth as target user]\n")
			b.WriteString("      |\n")
			b.WriteString("      v\n")
			b.WriteString("  [Domain Admin / target account compromised]\n")
			b.WriteString("```\n\n")
		}
	}

	// ESC2 paths
	for _, t := range result.Templates {
		for _, v := range t.ESCVulns {
			if v != "ESC2" {
				continue
			}
			pathIndex++
			b.WriteString(fmt.Sprintf("### Path %d: ESC2 via `%s`\n\n", pathIndex, t.Name))
			b.WriteString("```\n")
			b.WriteString(fmt.Sprintf("  [Attacker] --(enroll in Any Purpose EKU template)--> [Template: %s]\n", t.Name))
			b.WriteString("      |\n")
			b.WriteString("      v\n")
			b.WriteString("  [CA issues cert with Any Purpose EKU]\n")
			b.WriteString("      |\n")
			b.WriteString("      v\n")
			b.WriteString("  [Certificate valid for Client Auth / Smart Card Logon]\n")
			b.WriteString("      |\n")
			b.WriteString("      v\n")
			b.WriteString("  [PKINIT / Schannel auth as enrolled user]\n")
			b.WriteString("```\n\n")
		}
	}

	// ESC3 paths
	for _, t := range result.Templates {
		for _, v := range t.ESCVulns {
			if v != "ESC3" {
				continue
			}
			pathIndex++
			b.WriteString(fmt.Sprintf("### Path %d: ESC3 via `%s`\n\n", pathIndex, t.Name))
			b.WriteString("```\n")
			b.WriteString(fmt.Sprintf("  [Attacker] --(Stage 1: enroll in agent template)--> [Template: %s]\n", t.Name))
			b.WriteString("      |\n")
			b.WriteString("      v\n")
			b.WriteString("  [Obtain enrollment agent certificate]\n")
			b.WriteString("      |\n")
			b.WriteString("      v\n")
			b.WriteString("  [Stage 2: CMC co-signed enrollment on behalf of target]\n")
			b.WriteString("      |\n")
			b.WriteString("      v\n")
			b.WriteString("  [Certificate issued for target user -> domain compromise]\n")
			b.WriteString("```\n\n")
		}
	}

	// ESC4 paths
	for _, t := range result.Templates {
		if len(t.ESC4Findings) == 0 {
			continue
		}
		pathIndex++
		trustees := make([]string, 0, len(t.ESC4Findings))
		for _, f := range t.ESC4Findings {
			trustees = append(trustees, f.Trustee)
		}
		b.WriteString(fmt.Sprintf("### Path %d: ESC4 -> ESC1 via `%s`\n\n", pathIndex, t.Name))
		b.WriteString("```\n")
		b.WriteString(fmt.Sprintf("  [Attacker (%s)]\n", strings.Join(trustees, " or ")))
		b.WriteString("      |\n")
		b.WriteString(fmt.Sprintf("      --(WriteDACL/WriteOwner on template)--> [Template: %s]\n", t.Name))
		b.WriteString("      |\n")
		b.WriteString("      v\n")
		b.WriteString("  [Modify template: enable ENROLLEE_SUPPLIES_SUBJECT]\n")
		b.WriteString("      |\n")
		b.WriteString("      v\n")
		b.WriteString("  [Exploit as ESC1 -> forge cert -> domain compromise]\n")
		b.WriteString("      |\n")
		b.WriteString("      v\n")
		b.WriteString("  [Restore original template configuration]\n")
		b.WriteString("```\n\n")
	}

	// ESC5 paths
	if len(result.ESC5Findings) > 0 {
		pathIndex++
		b.WriteString(fmt.Sprintf("### Path %d: ESC5 — CA Object Takeover\n\n", pathIndex))
		b.WriteString("```\n")
		b.WriteString("  [Attacker with dangerous CA ACE]\n")
		b.WriteString("      |\n")
		b.WriteString("      --(WriteDACL/WriteOwner/GenericAll on CA object)-->\n")
		b.WriteString("      |\n")
		b.WriteString("      v\n")
		b.WriteString("  [Modify CA configuration / issue arbitrary certificates]\n")
		b.WriteString("      |\n")
		b.WriteString("      v\n")
		b.WriteString("  [Full PKI compromise -> domain compromise]\n")
		b.WriteString("```\n\n")
	}

	// ESC8 paths
	if len(result.ESC8Findings) > 0 {
		pathIndex++
		b.WriteString(fmt.Sprintf("### Path %d: ESC8 — NTLM Relay to Web Enrollment\n\n", pathIndex))
		b.WriteString("```\n")
		b.WriteString("  [Attacker] --(coerce NTLM auth: PetitPotam/PrinterBug)--> [Target Machine]\n")
		b.WriteString("      |\n")
		b.WriteString("      v\n")
		for _, f := range result.ESC8Findings {
			b.WriteString(fmt.Sprintf("  [Relay to %s (%s)]\n", f.HTTPEndpoint, f.CAName))
		}
		b.WriteString("      |\n")
		b.WriteString("      v\n")
		b.WriteString("  [CA issues certificate as relayed principal]\n")
		b.WriteString("      |\n")
		b.WriteString("      v\n")
		b.WriteString("  [Authenticate as machine/user account -> domain compromise]\n")
		b.WriteString("```\n\n")
	}

	// ESC9 paths
	if len(result.ESC9Findings) > 0 {
		pathIndex++
		b.WriteString(fmt.Sprintf("### Path %d: ESC9 — UPN Spoofing via Missing Security Extension\n\n", pathIndex))
		b.WriteString("```\n")
		b.WriteString("  [Attacker] --(modify own userPrincipalName to target UPN)-->\n")
		b.WriteString("      |\n")
		b.WriteString("      v\n")
		for _, f := range result.ESC9Findings {
			b.WriteString(fmt.Sprintf("  [Enroll in template: %s (NO_SECURITY_EXTENSION set)]\n", f.TemplateName))
		}
		b.WriteString("      |\n")
		b.WriteString("      v\n")
		b.WriteString("  [Certificate issued without requester SID extension]\n")
		b.WriteString("      |\n")
		b.WriteString("      v\n")
		b.WriteString("  [Restore original UPN -> authenticate with cert as target]\n")
		b.WriteString("```\n\n")
	}

	// ESC11 paths
	if len(result.ESC11Findings) > 0 {
		pathIndex++
		b.WriteString(fmt.Sprintf("### Path %d: ESC11 — NTLM Relay to RPC Interface\n\n", pathIndex))
		b.WriteString("```\n")
		b.WriteString("  [Attacker] --(coerce NTLM auth)--> [Target Machine]\n")
		b.WriteString("      |\n")
		b.WriteString("      v\n")
		for _, f := range result.ESC11Findings {
			b.WriteString(fmt.Sprintf("  [Relay to RPC on %s (CA: %s, encryption NOT enforced)]\n", f.CAHostname, f.CAName))
		}
		b.WriteString("      |\n")
		b.WriteString("      v\n")
		b.WriteString("  [Certificate issued via ICertPassage as relayed principal]\n")
		b.WriteString("```\n\n")
	}

	// ESC13 paths
	if len(result.ESC13Findings) > 0 {
		pathIndex++
		b.WriteString(fmt.Sprintf("### Path %d: ESC13 — OID Group Link Privilege Escalation\n\n", pathIndex))
		b.WriteString("```\n")
		for _, f := range result.ESC13Findings {
			b.WriteString(fmt.Sprintf("  [Attacker] --(enroll in template: %s)-->\n", f.TemplateName))
			b.WriteString(fmt.Sprintf("      | (issuance policy OID: %s)\n", f.IssuancePolicyOID))
			b.WriteString("      v\n")
			b.WriteString(fmt.Sprintf("  [Certificate contains OID linked to group: %s]\n", f.LinkedGroupName))
			b.WriteString("      |\n")
			b.WriteString("      v\n")
			b.WriteString(fmt.Sprintf("  [PKINIT auth -> TGT includes %s membership]\n", f.LinkedGroupName))
		}
		b.WriteString("```\n\n")
	}

	if pathIndex == 0 {
		b.WriteString("No exploitable attack paths identified.\n\n")
	}
}

// writeRemediation generates per-finding remediation recommendations.
func writeRemediation(b *strings.Builder, result EnumerationResult) {
	seen := make(map[string]bool)

	for _, t := range result.Templates {
		for _, v := range t.ESCVulns {
			if seen[v] {
				continue
			}
			seen[v] = true
			sev := escSeverity[v]
			if sev == "" {
				sev = "MEDIUM"
			}
			rem := escRemediation[v]
			if rem == "" {
				rem = "Review and restrict template/CA permissions. Consult Microsoft ADCS hardening guide."
			}
			b.WriteString(fmt.Sprintf("### %s [%s]\n\n", v, sev))
			if desc, ok := ESCDescription[v]; ok {
				b.WriteString(fmt.Sprintf("**Description:** %s  \n", desc.Name))
				b.WriteString(fmt.Sprintf("**Impact:** %s  \n\n", desc.Impact))
			}
			b.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", rem))
		}
	}

	// ESC5 from scan results (not template-level)
	if len(result.ESC5Findings) > 0 && !seen["ESC5"] {
		seen["ESC5"] = true
		b.WriteString(fmt.Sprintf("### ESC5 [%s]\n\n", escSeverity["ESC5"]))
		if desc, ok := ESCDescription["ESC5"]; ok {
			b.WriteString(fmt.Sprintf("**Description:** %s  \n", desc.Name))
			b.WriteString(fmt.Sprintf("**Impact:** %s  \n\n", desc.Impact))
		}
		b.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", escRemediation["ESC5"]))
	}

	// ESC8
	if len(result.ESC8Findings) > 0 && !seen["ESC8"] {
		seen["ESC8"] = true
		b.WriteString(fmt.Sprintf("### ESC8 [%s]\n\n", escSeverity["ESC8"]))
		if desc, ok := ESCDescription["ESC8"]; ok {
			b.WriteString(fmt.Sprintf("**Description:** %s  \n", desc.Name))
			b.WriteString(fmt.Sprintf("**Impact:** %s  \n\n", desc.Impact))
		}
		b.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", escRemediation["ESC8"]))
	}

	// ESC9
	if len(result.ESC9Findings) > 0 && !seen["ESC9"] {
		seen["ESC9"] = true
		b.WriteString(fmt.Sprintf("### ESC9 [%s]\n\n", escSeverity["ESC9"]))
		if desc, ok := ESCDescription["ESC9"]; ok {
			b.WriteString(fmt.Sprintf("**Description:** %s  \n", desc.Name))
			b.WriteString(fmt.Sprintf("**Impact:** %s  \n\n", desc.Impact))
		}
		b.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", escRemediation["ESC9"]))
	}

	// ESC11
	if len(result.ESC11Findings) > 0 && !seen["ESC11"] {
		seen["ESC11"] = true
		b.WriteString(fmt.Sprintf("### ESC11 [%s]\n\n", escSeverity["ESC11"]))
		if desc, ok := ESCDescription["ESC11"]; ok {
			b.WriteString(fmt.Sprintf("**Description:** %s  \n", desc.Name))
			b.WriteString(fmt.Sprintf("**Impact:** %s  \n\n", desc.Impact))
		}
		b.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", escRemediation["ESC11"]))
	}

	// ESC10
	if len(result.ESC10Findings) > 0 && !seen["ESC10"] {
		seen["ESC10"] = true
		b.WriteString(fmt.Sprintf("### ESC10 [%s]\n\n", escSeverity["ESC10"]))
		if desc, ok := ESCDescription["ESC10"]; ok {
			b.WriteString(fmt.Sprintf("**Description:** %s  \n", desc.Name))
			b.WriteString(fmt.Sprintf("**Impact:** %s  \n\n", desc.Impact))
		}
		b.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", escRemediation["ESC10"]))
	}

	// ESC12
	if len(result.ESC12Findings) > 0 && !seen["ESC12"] {
		seen["ESC12"] = true
		b.WriteString(fmt.Sprintf("### ESC12 [%s]\n\n", escSeverity["ESC12"]))
		if desc, ok := ESCDescription["ESC12"]; ok {
			b.WriteString(fmt.Sprintf("**Description:** %s  \n", desc.Name))
			b.WriteString(fmt.Sprintf("**Impact:** %s  \n\n", desc.Impact))
		}
		b.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", escRemediation["ESC12"]))
	}

	// ESC13
	if len(result.ESC13Findings) > 0 && !seen["ESC13"] {
		seen["ESC13"] = true
		b.WriteString(fmt.Sprintf("### ESC13 [%s]\n\n", escSeverity["ESC13"]))
		if desc, ok := ESCDescription["ESC13"]; ok {
			b.WriteString(fmt.Sprintf("**Description:** %s  \n", desc.Name))
			b.WriteString(fmt.Sprintf("**Impact:** %s  \n\n", desc.Impact))
		}
		b.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", escRemediation["ESC13"]))
	}

	// ESC14
	if len(result.ESC14Findings) > 0 && !seen["ESC14"] {
		seen["ESC14"] = true
		b.WriteString(fmt.Sprintf("### ESC14 [%s]\n\n", escSeverity["ESC14"]))
		if desc, ok := ESCDescription["ESC14"]; ok {
			b.WriteString(fmt.Sprintf("**Description:** %s  \n", desc.Name))
			b.WriteString(fmt.Sprintf("**Impact:** %s  \n\n", desc.Impact))
		}
		b.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", escRemediation["ESC14"]))
	}
}

// countSeverities counts findings by severity level across all result categories.
func countSeverities(result EnumerationResult) (critical, high, medium int) {
	for _, t := range result.Templates {
		for _, v := range t.ESCVulns {
			switch escSeverity[v] {
			case "CRITICAL":
				critical++
			case "HIGH":
				high++
			case "MEDIUM":
				medium++
			}
		}
	}
	// ESC5 findings are CRITICAL, ESC6 is CRITICAL
	critical += len(result.ESC5Findings) + len(result.ESC6Findings)
	// ESC2, ESC3, ESC7, ESC8, ESC9, ESC10, ESC11, ESC12, ESC13, ESC14 are HIGH
	high += len(result.ESC2Findings) + len(result.ESC3Findings) +
		len(result.ESC7Findings) + len(result.ESC8Findings) + len(result.ESC9Findings) +
		len(result.ESC10Findings) + len(result.ESC11Findings) + len(result.ESC12Findings) +
		len(result.ESC13Findings) + len(result.ESC14Findings)

	return
}

// truncateDN shortens a distinguished name to max length for table display.
func truncateDN(dn string, max int) string {
	if len(dn) <= max {
		return dn
	}
	return dn[:max-3] + "..."
}
