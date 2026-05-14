package pki

import (
	"strings"
	"testing"
)

func TestGenerateReport_Markdown_EmptyFindings(t *testing.T) {
	result := EnumerationResult{
		Domain:   "corp.local",
		TargetDC: "dc01.corp.local",
	}

	data, err := GenerateReport(result, "markdown")
	if err != nil {
		t.Fatalf("GenerateReport: %v", err)
	}
	report := string(data)

	if !strings.Contains(report, "Trusted ADCS Security Assessment Report") {
		t.Error("report missing title")
	}
	if !strings.Contains(report, "corp.local") {
		t.Error("report missing domain")
	}
	if !strings.Contains(report, "No exploitable ADCS misconfigurations") {
		t.Error("empty report should say no findings")
	}
	if !strings.Contains(report, "No exploitable attack paths identified") {
		t.Error("empty report should say no attack paths")
	}
}

func TestGenerateReport_Markdown_WithFindings(t *testing.T) {
	result := EnumerationResult{
		Domain:     "corp.local",
		TargetDC:   "dc01.corp.local",
		TotalScore: 18,
		Templates: []CertTemplate{
			{
				Name:                    "VulnESC1",
				ESCScore:                10,
				ESCVulns:                []string{"ESC1"},
				EnrolleeSuppliesSubject: true,
				AuthenticationEKU:       true,
				SchemaVersion:           2,
				EKUs:                    []string{ekuClientAuth},
			},
			{
				Name:     "SafeTemplate",
				ESCScore: 0,
			},
		},
		ESC8Findings: []ESC8Finding{
			{
				CAName:       "CorpCA",
				CAHostname:   "ca01.corp.local",
				HTTPEndpoint: "http://ca01.corp.local/certsrv/",
				NTLMEnabled:  true,
				Templates:    []string{"Machine", "User"},
			},
		},
	}

	data, err := GenerateReport(result, "markdown")
	if err != nil {
		t.Fatalf("GenerateReport: %v", err)
	}
	report := string(data)

	// Executive summary severity table
	if !strings.Contains(report, "CRITICAL") {
		t.Error("report should contain CRITICAL severity")
	}
	if !strings.Contains(report, "finding(s)") {
		t.Error("report should contain findings count")
	}

	// Template findings table
	if !strings.Contains(report, "VulnESC1") {
		t.Error("report should contain vulnerable template name")
	}
	if !strings.Contains(report, "Certificate Template Findings") {
		t.Error("report should contain template findings section")
	}

	// ESC8 section
	if !strings.Contains(report, "ESC8") {
		t.Error("report should contain ESC8 section")
	}
	if !strings.Contains(report, "ca01.corp.local") {
		t.Error("report should contain CA hostname")
	}

	// Attack path diagrams
	if !strings.Contains(report, "ESC1 via") {
		t.Error("report should contain ESC1 attack path diagram")
	}
	if !strings.Contains(report, "NTLM Relay to Web Enrollment") {
		t.Error("report should contain ESC8 attack path")
	}

	// Remediation
	if !strings.Contains(report, "Remediation") {
		t.Error("report should contain remediation section")
	}
	if !strings.Contains(report, "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT") {
		t.Error("ESC1 remediation should mention the flag to remove")
	}

	// Appendix — should list ALL templates (including safe ones)
	if !strings.Contains(report, "SafeTemplate") {
		t.Error("appendix should list all templates including safe ones")
	}
}

func TestGenerateReport_UnsupportedFormat(t *testing.T) {
	_, err := GenerateReport(EnumerationResult{}, "pdf")
	if err == nil {
		t.Error("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("error should mention unsupported format, got: %v", err)
	}
}

func TestGenerateReport_Markdown_ESC9Findings(t *testing.T) {
	result := EnumerationResult{
		Domain:   "corp.local",
		TargetDC: "dc01",
		ESC9Findings: []ESC9Finding{
			{
				TemplateName:           "NoSecExt",
				HasNoSecurityExtension: true,
				AuthenticationEKU:      true,
				BindingEnforcement:     1,
			},
		},
	}
	data, err := GenerateReport(result, "md")
	if err != nil {
		t.Fatalf("GenerateReport: %v", err)
	}
	report := string(data)

	if !strings.Contains(report, "ESC9") {
		t.Error("report should contain ESC9 section")
	}
	if !strings.Contains(report, "NoSecExt") {
		t.Error("report should contain ESC9 template name")
	}
	if !strings.Contains(report, "Compatibility (EXPLOITABLE)") {
		t.Error("report should show binding enforcement level")
	}
}

func TestCountSeverities(t *testing.T) {
	result := EnumerationResult{
		Templates: []CertTemplate{
			{ESCVulns: []string{"ESC1"}},       // CRITICAL
			{ESCVulns: []string{"ESC2"}},       // HIGH (from template vuln)
			{ESCVulns: []string{"ESC4-CHECK"}}, // MEDIUM
		},
		ESC8Findings: []ESC8Finding{{}, {}}, // 2 HIGH
		ESC5Findings: []ESC5Finding{{}},     // 1 CRITICAL
	}

	crit, high, med := countSeverities(result)
	if crit != 2 { // ESC1 + ESC5
		t.Errorf("expected 2 critical, got %d", crit)
	}
	if high != 3 { // ESC2 (template) + 2x ESC8
		t.Errorf("expected 3 high, got %d", high)
	}
	if med != 1 { // ESC4-CHECK
		t.Errorf("expected 1 medium, got %d", med)
	}
}

func TestTruncateDN(t *testing.T) {
	short := "CN=Test,DC=corp"
	if truncateDN(short, 50) != short {
		t.Error("short DN should not be truncated")
	}

	long := "CN=VeryLongName,OU=SubOU,OU=TopOU,DC=corp,DC=local,DC=example"
	result := truncateDN(long, 20)
	if len(result) > 20 {
		t.Errorf("truncated DN too long: %d chars", len(result))
	}
	if !strings.HasSuffix(result, "...") {
		t.Error("truncated DN should end with ...")
	}
}
