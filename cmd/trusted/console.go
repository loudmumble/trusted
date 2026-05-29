package main

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/loudmumble/trusted/internal/tui"
)

func runConsole(c2URL string) error {
	p := tea.NewProgram(tui.NewModel(c2URL), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}
	return nil
}
