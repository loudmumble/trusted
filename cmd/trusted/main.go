package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "1.0.0"

var rootCmd = &cobra.Command{
	Use:           "trusted",
	Short:         "Trusted — AD Trust Attack Framework",
	SilenceUsage:  true,
	SilenceErrors: true,
	Long: `Trusted is a pure Go Active Directory trust attack framework with integrated C2.
Abuses certificate trust, delegation trust, GPO trust, and authentication trust.

Usage:
  trusted pki --enum --target-dc dc01.corp.local --domain corp.local
  trusted delegation enum --target-dc dc01 --domain corp.local -u user -p pass
  trusted gpo --enum --target-dc dc01 --domain corp.local -u user -p pass
  trusted c2 --bind 0.0.0.0 --port 8443 --protocol https`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Trusted v%s\n", version)
		return cmd.Help()
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
