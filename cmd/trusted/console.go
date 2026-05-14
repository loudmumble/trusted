package main

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/loudmumble/trusted/internal/tui"
	"github.com/spf13/cobra"
)

var consoleCmd = &cobra.Command{
	Use:   "console",
	Short: "Launch the operator console TUI",
	Long: `Launch the Bubbletea operator console for C2 session management.

Views:
  [1] Sessions  — Active implant sessions with host/user/IP/last-seen
  [2] Commands  — Command input, history, and results for selected session
  [3] Listeners — Active C2 listener status
  [4] Implants  — Configured implant configurations
  [5] PKI      — Certificate and ADCS attack status

Keybindings:
  1-5    Switch views
  tab    Cycle views
  j/k    Navigate up/down
  enter  Select session
  i      Input command (Commands view)
  q      Quit`,
	RunE: func(cmd *cobra.Command, args []string) error {
		c2URL, _ := cmd.Flags().GetString("c2-url")
		p := tea.NewProgram(tui.NewModel(c2URL), tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			return fmt.Errorf("TUI error: %w", err)
		}
		return nil
	},
}

func init() {
	consoleCmd.Flags().String("c2-url", "http://localhost:8080", "C2 listener URL to poll for live data")
	rootCmd.AddCommand(consoleCmd)
}
