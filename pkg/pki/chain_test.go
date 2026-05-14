package pki

import (
	"strings"
	"testing"
)

func TestScoreESC_ESC2_AnyPurpose(t *testing.T) {
	tmpl := CertTemplate{
		EnrolleeSuppliesSubject: true,
		AuthenticationEKU:       true,
		EKUs:                    []string{ekuAnyPurpose},
	}
	scoreESC(&tmpl)
	found := false
	for _, v := range tmpl.ESCVulns {
		if v == "ESC2" {
			found = true
		}
	}
	if !found {
		t.Error("expected ESC2 for template with Any Purpose EKU + enrollee supplies subject")
	}
}

func TestScoreESC_ESC2_EmptyEKUs(t *testing.T) {
	tmpl := CertTemplate{
		EnrolleeSuppliesSubject: true,
		AuthenticationEKU:       true,
		EKUs:                    []string{}, // empty = any purpose
	}
	scoreESC(&tmpl)
	found := false
	for _, v := range tmpl.ESCVulns {
		if v == "ESC2" {
			found = true
		}
	}
	if !found {
		t.Error("expected ESC2 for template with empty EKU list (implicit any purpose) + enrollee supplies subject")
	}
}

func TestScoreESC_ESC3(t *testing.T) {
	tmpl := CertTemplate{
		EKUs: []string{"1.3.6.1.4.1.311.20.2.1"}, // Certificate Request Agent
	}
	scoreESC(&tmpl)
	found := false
	for _, v := range tmpl.ESCVulns {
		if v == "ESC3" {
			found = true
		}
	}
	if !found {
		t.Error("expected ESC3 for template with Certificate Request Agent EKU")
	}
}

func TestScoreESC_NonVulnerable(t *testing.T) {
	tmpl := CertTemplate{
		Name:                    "SafeTemplate",
		EnrolleeSuppliesSubject: false,
		AuthenticationEKU:       true,
		EKUs:                    []string{ekuClientAuth},
	}
	scoreESC(&tmpl)
	if len(tmpl.ESCVulns) != 0 {
		t.Errorf("expected no vulns for safe template, got %v", tmpl.ESCVulns)
	}
	if tmpl.ESCScore != 0 {
		t.Errorf("expected score 0 for safe template, got %d", tmpl.ESCScore)
	}
}

func TestBuildSteps_ESC1(t *testing.T) {
	cfg := &ADCSConfig{Domain: "corp.local", TargetDC: "dc01", Username: "user"}
	tmpl := CertTemplate{Name: "VulnTemplate"}
	steps := buildSteps("ESC1", tmpl, cfg)

	if len(steps) < 3 {
		t.Fatalf("expected at least 3 steps for ESC1, got %d", len(steps))
	}
	// Last step should be the trusted command
	lastStep := steps[len(steps)-1]
	if !strings.Contains(lastStep, "trusted pki --esc 1") {
		t.Errorf("ESC1 step should contain trusted command, got: %s", lastStep)
	}
	if !strings.Contains(lastStep, "--template VulnTemplate") {
		t.Errorf("ESC1 step should reference template name, got: %s", lastStep)
	}
}

func TestBuildSteps_ESC11_NtlmrelayxNotFabricated(t *testing.T) {
	cfg := &ADCSConfig{Domain: "corp.local", TargetDC: "dc01"}
	tmpl := CertTemplate{Name: "Machine"}
	steps := buildSteps("ESC11", tmpl, cfg)

	for _, step := range steps {
		if strings.Contains(step, "-rpc-mode") {
			t.Errorf("ESC11 steps should NOT contain fabricated -rpc-mode flag: %s", step)
		}
		if strings.Contains(step, "-icpr-ca-name") {
			t.Errorf("ESC11 steps should NOT contain fabricated -icpr-ca-name flag: %s", step)
		}
	}

	// Should use certipy-ad relay instead
	found := false
	for _, step := range steps {
		if strings.Contains(step, "certipy-ad relay") {
			found = true
		}
	}
	if !found {
		t.Error("ESC11 steps should suggest certipy-ad relay command")
	}
}

func TestBuildSteps_ESC12_NtlmrelayxNotFabricated(t *testing.T) {
	cfg := &ADCSConfig{Domain: "corp.local", TargetDC: "dc01"}
	tmpl := CertTemplate{Name: "Machine"}
	steps := buildSteps("ESC12", tmpl, cfg)

	for _, step := range steps {
		if strings.Contains(step, "-dcom-mode") {
			t.Errorf("ESC12 steps should NOT contain fabricated -dcom-mode flag: %s", step)
		}
	}

	found := false
	for _, step := range steps {
		if strings.Contains(step, "certipy-ad relay") {
			found = true
		}
	}
	if !found {
		t.Error("ESC12 steps should suggest certipy-ad relay command")
	}
}

func TestBuildSteps_ESC8(t *testing.T) {
	cfg := &ADCSConfig{Domain: "corp.local", TargetDC: "dc01"}
	tmpl := CertTemplate{Name: "Machine"}
	steps := buildSteps("ESC8", tmpl, cfg)

	found := false
	for _, step := range steps {
		if strings.Contains(step, "ntlmrelayx.py -t http://") && strings.Contains(step, "certfnsh.asp") {
			found = true
		}
	}
	if !found {
		t.Error("ESC8 steps should contain ntlmrelayx.py command with HTTP URL")
	}
}

func TestPrintAttackChain_Empty(t *testing.T) {
	out := captureStdout(t, func() { PrintAttackChain(nil) })
	if !strings.Contains(out, "No exploitable attack paths found") {
		t.Error("empty chain should print 'no paths found' message")
	}
}

func TestPrintAttackChain_WithPaths(t *testing.T) {
	paths := []AttackPath{
		{
			Priority:    1,
			ESCType:     "ESC1",
			Template:    CertTemplate{Name: "TestTemplate", ESCScore: 10, ESCVulns: []string{"ESC1"}},
			Description: "Misconfigured Certificate Templates",
			Impact:      "Domain Admin impersonation",
			Difficulty:  "Low",
			Steps:       []string{"Step 1", "Step 2"},
		},
	}

	out := captureStdout(t, func() { PrintAttackChain(paths) })
	if !strings.Contains(out, "ESC1") {
		t.Error("output should contain ESC type")
	}
	if !strings.Contains(out, "TestTemplate") {
		t.Error("output should contain template name")
	}
	if !strings.Contains(out, "Step 1") {
		t.Error("output should contain steps")
	}
}
