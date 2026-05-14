package pki

import (
	"context"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"sync"
)

// EnumerationResult holds all scan results from a full ADCS enumeration pass.
// Designed for structured JSON output and report generation.
type EnumerationResult struct {
	Domain        string         `json:"domain"`
	TargetDC      string         `json:"target_dc"`
	Errors        []string       `json:"errors,omitempty"`
	Templates     []CertTemplate `json:"templates"`
	ESC2Findings  []ESC2Finding  `json:"esc2_findings"`
	ESC3Findings  []ESC3Finding  `json:"esc3_findings"`
	ESC5Findings  []ESC5Finding  `json:"esc5_findings"`
	ESC6Findings  []ESC6Finding  `json:"esc6_findings"`
	ESC7Findings  []ESC7Finding  `json:"esc7_findings"`
	ESC8Findings  []ESC8Finding  `json:"esc8_findings"`
	ESC9Findings  []ESC9Finding  `json:"esc9_findings"`
	ESC10Findings []ESC10Finding `json:"esc10_findings"`
	ESC11Findings []ESC11Finding `json:"esc11_findings"`
	ESC12Findings []ESC12Finding `json:"esc12_findings"`
	ESC13Findings []ESC13Finding `json:"esc13_findings"`
	ESC14Findings []ESC14Finding `json:"esc14_findings"`
	VulnCount     int            `json:"vuln_count"`
	TotalScore    int            `json:"total_score"`
}

// EnumerateAll performs a comprehensive ADCS scan: template enumeration plus all ESC scans.
// Returns a structured EnumerationResult suitable for JSON output or report generation.
func EnumerateAll(ctx context.Context, cfg *ADCSConfig, conn *ldap.Conn) (EnumerationResult, error) {
	result := EnumerationResult{
		Domain:   cfg.Domain,
		TargetDC: cfg.TargetDC,
	}

	templates, err := EnumerateTemplates(ctx, cfg, conn)
	if err != nil {
		return result, fmt.Errorf("enumerate templates: %w", err)
	}
	result.Templates = templates

	var mu sync.Mutex
	var wg sync.WaitGroup

	runScan := func(name string, scanFunc func() (interface{}, error), assignFunc func(interface{})) {
		if cfg.Stealth {
			stealthDelay(cfg)
			res, err := scanFunc()
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s scan failed: %v", name, err))
			} else {
				assignFunc(res)
			}
		} else {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := scanFunc()
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("%s scan failed: %v", name, err))
				} else {
					assignFunc(res)
				}
			}()
		}
	}

	runScan("ESC2", func() (interface{}, error) { return ScanESC2(ctx, cfg, conn) }, func(res interface{}) { result.ESC2Findings = res.([]ESC2Finding) })
	runScan("ESC3", func() (interface{}, error) { return ScanESC3(ctx, cfg, conn) }, func(res interface{}) { result.ESC3Findings = res.([]ESC3Finding) })
	runScan("ESC5", func() (interface{}, error) { return ScanESC5(ctx, cfg, conn) }, func(res interface{}) { result.ESC5Findings = res.([]ESC5Finding) })
	runScan("ESC6", func() (interface{}, error) { return ScanESC6(ctx, cfg, conn) }, func(res interface{}) { result.ESC6Findings = res.([]ESC6Finding) })
	runScan("ESC7", func() (interface{}, error) { return ScanESC7(ctx, cfg, conn) }, func(res interface{}) { result.ESC7Findings = res.([]ESC7Finding) })
	runScan("ESC8", func() (interface{}, error) { return ScanESC8(ctx, cfg, conn) }, func(res interface{}) { result.ESC8Findings = res.([]ESC8Finding) })
	runScan("ESC9", func() (interface{}, error) { return ScanESC9(ctx, cfg, conn) }, func(res interface{}) { result.ESC9Findings = res.([]ESC9Finding) })
	runScan("ESC10", func() (interface{}, error) { return ScanESC10(ctx, cfg, conn) }, func(res interface{}) { result.ESC10Findings = res.([]ESC10Finding) })
	runScan("ESC11", func() (interface{}, error) { return ScanESC11(ctx, cfg, conn) }, func(res interface{}) { result.ESC11Findings = res.([]ESC11Finding) })
	runScan("ESC12", func() (interface{}, error) { return ScanESC12(ctx, cfg, conn) }, func(res interface{}) { result.ESC12Findings = res.([]ESC12Finding) })
	runScan("ESC13", func() (interface{}, error) { return ScanESC13(ctx, cfg, conn) }, func(res interface{}) { result.ESC13Findings = res.([]ESC13Finding) })
	runScan("ESC14", func() (interface{}, error) { return ScanESC14(ctx, cfg, conn) }, func(res interface{}) { result.ESC14Findings = res.([]ESC14Finding) })

	if !cfg.Stealth {
		wg.Wait()
	}

	for _, t := range result.Templates {
		if t.ESCScore > 0 {
			result.VulnCount++
			result.TotalScore += t.ESCScore
		}
	}
	result.VulnCount += len(result.ESC2Findings) + len(result.ESC3Findings) +
		len(result.ESC5Findings) + len(result.ESC6Findings) + len(result.ESC7Findings) +
		len(result.ESC8Findings) + len(result.ESC9Findings) + len(result.ESC10Findings) +
		len(result.ESC11Findings) + len(result.ESC12Findings) + len(result.ESC13Findings) + len(result.ESC14Findings)

	return result, nil
}

// ExploitResult holds structured output from an exploitation run.
type ExploitResult struct {
	Exploit      string `json:"exploit"`
	Template     string `json:"template"`
	TargetUPN    string `json:"target_upn"`
	CertPath     string `json:"cert_path,omitempty"`
	KeyPath      string `json:"key_path,omitempty"`
	PFXPath      string `json:"pfx_path,omitempty"`
	Success      bool   `json:"success"`
	ErrorMessage string `json:"error_message,omitempty"`
}
