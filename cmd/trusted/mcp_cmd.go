package main

import (
	"fmt"

	"github.com/loudmumble/trusted/internal/mcp"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start MCP stdio server for agentic integration",
	Long: `Run Trusted as an MCP (Model Context Protocol) server over stdio.

Tools available:
  pki_enumerate    — Enumerate ADCS certificate templates
  pki_forge        — Forge golden certificates
  c2_list_sessions — List active C2 sessions
  c2_queue_command — Queue command for session
  c2_get_results   — Get command results`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := mcp.ServeStdio(nil); err != nil {
			return fmt.Errorf("MCP server error: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}
