package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "1.0.0"

var rootCmd = &cobra.Command{
	Use:           "trusted",
	Aliases:       []string{"ted"},
	Short:         "Trusted — AD Trust Attack Framework",
	SilenceUsage:  true,
	SilenceErrors: true,
	Long: `Trusted is a pure Go Active Directory trust attack framework with integrated C2.
Abuses certificate trust, delegation trust, GPO trust, and authentication trust.

'Ted' can be used as an alias for 'trusted'.

Usage:
  trusted esc 1 -t Vuln -U admin@corp.local -d corp.local -dc dc01
  trusted enum -d corp.local -dc dc01
  trusted deleg enum -d corp.local -dc dc01
  trusted gpo enum -d corp.local -dc dc01
  trusted c2 start -b 0.0.0.0 -p 8443`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Trusted v%s\n", version)
		return cmd.Help()
	},
}

func init() {
	// Root-level persistent flags — inherited by ALL commands
	rootCmd.PersistentFlags().String("dc", "", "Target DC hostname")
	rootCmd.PersistentFlags().String("dc-ip", "", "KDC IP (if different from -dc)")
	rootCmd.PersistentFlags().StringP("domain", "d", "", "Active Directory domain")
	rootCmd.PersistentFlags().StringP("username", "u", "", "Domain username")
	rootCmd.PersistentFlags().StringP("password", "p", "", "Domain password")
	rootCmd.PersistentFlags().StringP("hash", "H", "", "NTLM hash (pass-the-hash)")
	rootCmd.PersistentFlags().BoolP("kerberos", "k", false, "Use Kerberos auth (GSSAPI/SPNEGO)")
	rootCmd.PersistentFlags().StringP("ccache", "C", "", "Kerberos ccache path")
	rootCmd.PersistentFlags().StringP("keytab", "K", "", "Kerberos keytab path")
	rootCmd.PersistentFlags().BoolP("ldaps", "L", false, "Use LDAPS (port 636)")
	rootCmd.PersistentFlags().BoolP("start-tls", "S", false, "Use StartTLS")
	rootCmd.PersistentFlags().BoolP("stealth", "s", false, "Stealth mode (jittered queries)")
	rootCmd.PersistentFlags().Int("timeout", 10, "Network timeout (seconds)")
	rootCmd.PersistentFlags().BoolP("json", "j", false, "JSON output")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
