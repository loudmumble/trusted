package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestNewModel(t *testing.T) {
	m := NewModel("")
	if m.view != ViewSessions {
		t.Errorf("expected initial view ViewSessions, got %d", m.view)
	}
	if len(m.sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(m.sessions))
	}
	if len(m.listeners) != 0 {
		t.Errorf("expected 0 listeners (empty by default), got %d", len(m.listeners))
	}
	if len(m.implants) != 0 {
		t.Errorf("expected 0 implants (empty by default), got %d", len(m.implants))
	}
	if m.statusMsg != "Ready" {
		t.Errorf("expected status 'Ready', got %q", m.statusMsg)
	}
}

func TestViewConstants(t *testing.T) {
	if ViewSessions != 0 {
		t.Errorf("ViewSessions should be 0, got %d", ViewSessions)
	}
	if ViewCommands != 1 {
		t.Errorf("ViewCommands should be 1, got %d", ViewCommands)
	}
	if ViewListeners != 2 {
		t.Errorf("ViewListeners should be 2, got %d", ViewListeners)
	}
	if ViewImplants != 3 {
		t.Errorf("ViewImplants should be 3, got %d", ViewImplants)
	}
	if ViewPKI != 4 {
		t.Errorf("ViewPKI should be 4, got %d", ViewPKI)
	}
}

func TestWindowSizeMsg(t *testing.T) {
	m := NewModel("")
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	um := updated.(Model)
	if um.width != 120 || um.height != 40 {
		t.Errorf("expected 120x40, got %dx%d", um.width, um.height)
	}
}

func TestKeyNavigation(t *testing.T) {
	m := NewModel("")

	// Switch to Commands view
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	um := updated.(Model)
	if um.view != ViewCommands {
		t.Errorf("pressing '2' should switch to Commands view, got %d", um.view)
	}

	// Switch to Listeners view
	updated, _ = um.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	um = updated.(Model)
	if um.view != ViewListeners {
		t.Errorf("pressing '3' should switch to Listeners view, got %d", um.view)
	}

	// Switch to Implants view
	updated, _ = um.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'4'}})
	um = updated.(Model)
	if um.view != ViewImplants {
		t.Errorf("pressing '4' should switch to Implants view, got %d", um.view)
	}

	// Switch to PKI view
	updated, _ = um.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'5'}})
	um = updated.(Model)
	if um.view != ViewPKI {
		t.Errorf("pressing '5' should switch to PKI view, got %d", um.view)
	}

	// Switch back to Sessions
	updated, _ = um.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	um = updated.(Model)
	if um.view != ViewSessions {
		t.Errorf("pressing '1' should switch to Sessions view, got %d", um.view)
	}
}

func TestTabCycle(t *testing.T) {
	m := NewModel("")
	if m.view != ViewSessions {
		t.Fatal("expected initial view ViewSessions")
	}

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	um := updated.(Model)
	if um.view != ViewCommands {
		t.Errorf("tab from Sessions should go to Commands, got %d", um.view)
	}
}

func TestMoveSelection(t *testing.T) {
	m := NewModel("")
	m.sessions = []Session{
		{ID: "aaa", Hostname: "host1"},
		{ID: "bbb", Hostname: "host2"},
		{ID: "ccc", Hostname: "host3"},
	}

	m.moveSelection(1)
	if m.selectedIdx != 1 {
		t.Errorf("expected selectedIdx 1, got %d", m.selectedIdx)
	}

	m.moveSelection(1)
	if m.selectedIdx != 2 {
		t.Errorf("expected selectedIdx 2, got %d", m.selectedIdx)
	}

	// Should clamp at max
	m.moveSelection(1)
	if m.selectedIdx != 2 {
		t.Errorf("expected selectedIdx clamped at 2, got %d", m.selectedIdx)
	}

	// Move up
	m.moveSelection(-1)
	if m.selectedIdx != 1 {
		t.Errorf("expected selectedIdx 1, got %d", m.selectedIdx)
	}

	// Should clamp at 0
	m.moveSelection(-5)
	if m.selectedIdx != 0 {
		t.Errorf("expected selectedIdx clamped at 0, got %d", m.selectedIdx)
	}
}

func TestMoveSelection_EmptyList(t *testing.T) {
	m := NewModel("")
	m.moveSelection(1)
	if m.selectedIdx != 0 {
		t.Errorf("expected selectedIdx 0 on empty list, got %d", m.selectedIdx)
	}
}

func TestRenderSessions_Empty(t *testing.T) {
	m := NewModel("")
	output := m.renderSessions()
	if !strings.Contains(output, "No active sessions") {
		t.Error("expected 'No active sessions' message for empty session list")
	}
}

func TestRenderSessions_WithData(t *testing.T) {
	m := NewModel("")
	m.sessions = []Session{
		{ID: "abcdef1234567890", Hostname: "WORKSTATION", Username: "admin", OS: "windows", RemoteAddr: "10.0.0.5", LastCheckin: time.Now()},
	}
	output := m.renderSessions()
	if !strings.Contains(output, "WORKSTATION") {
		t.Error("expected hostname in session view")
	}
	if !strings.Contains(output, "admin") {
		t.Error("expected username in session view")
	}
}

func TestRenderCommands_NoSession(t *testing.T) {
	m := NewModel("")
	output := m.renderCommands()
	if !strings.Contains(output, "no session selected") {
		t.Error("expected 'no session selected' in commands view")
	}
}

func TestRenderCommands_WithData(t *testing.T) {
	m := NewModel("")
	m.selectedSession = "abcdef1234567890"
	m.commands = []CommandEntry{
		{ID: "cmd-1", Command: "whoami", Queued: time.Now(), Done: true, Output: "admin"},
	}
	output := m.renderCommands()
	if !strings.Contains(output, "whoami") {
		t.Error("expected command text in output")
	}
	if !strings.Contains(output, "✓") {
		t.Error("expected checkmark for completed command")
	}
}

func TestRenderListeners(t *testing.T) {
	m := NewModel("")
	// Model starts empty; verify empty state message
	output := m.renderListeners()
	if !strings.Contains(output, "No active listeners") {
		t.Error("expected 'No active listeners' for empty default model")
	}
}

func TestRenderListeners_Empty(t *testing.T) {
	m := NewModel("")
	m.listeners = nil
	output := m.renderListeners()
	if !strings.Contains(output, "No active listeners") {
		t.Error("expected 'No active listeners' message")
	}
}

func TestRenderImplants(t *testing.T) {
	m := NewModel("")
	// Model starts empty; verify empty state message
	output := m.renderImplants()
	if !strings.Contains(output, "No implant configurations") {
		t.Error("expected 'No implant configurations' for empty default model")
	}
}

func TestRenderImplants_Empty(t *testing.T) {
	m := NewModel("")
	m.implants = nil
	output := m.renderImplants()
	if !strings.Contains(output, "No implant configurations") {
		t.Error("expected empty implant message")
	}
}

func TestRenderPKI_Empty(t *testing.T) {
	m := NewModel("")
	output := m.renderPKI()
	if !strings.Contains(output, "No templates enumerated") {
		t.Error("expected empty PKI message")
	}
}

func TestRenderPKI_WithData(t *testing.T) {
	m := NewModel("")
	m.pkiTemplates = []PKITemplateInfo{
		{Name: "User", ESCVulns: []string{"ESC1"}, ESCScore: 10, EnrolleeSuppliesSubject: true, AuthenticationEKU: true},
		{Name: "WebServer", ESCVulns: nil, ESCScore: 0},
	}
	output := m.renderPKI()
	if !strings.Contains(output, "User") {
		t.Error("expected template name 'User' in PKI view")
	}
	if !strings.Contains(output, "ESC1") {
		t.Error("expected ESC1 vulnerability in PKI view")
	}
	if !strings.Contains(output, "2 templates") {
		t.Error("expected template count in PKI view")
	}
}

func TestView_ContainsBanner(t *testing.T) {
	m := NewModel("")
	output := m.View()
	if !strings.Contains(output, "TRUSTED") {
		t.Error("expected TRUSTED banner in view output")
	}
}

func TestView_ContainsStatusBar(t *testing.T) {
	m := NewModel("")
	output := m.View()
	if !strings.Contains(output, "q:quit") {
		t.Error("expected keybinding hints in status bar")
	}
}

func TestRenderTabs(t *testing.T) {
	m := NewModel("")
	tabs := m.renderTabs()
	if !strings.Contains(tabs, "Sessions") {
		t.Error("expected Sessions tab")
	}
	if !strings.Contains(tabs, "PKI") {
		t.Error("expected PKI tab")
	}
}

func TestTickMsg(t *testing.T) {
	m := NewModel("")
	before := m.lastRefresh
	time.Sleep(1 * time.Millisecond)
	updated, cmd := m.Update(tickMsg(time.Now()))
	um := updated.(Model)
	if !um.lastRefresh.After(before) {
		t.Error("expected lastRefresh to be updated after tick")
	}
	if cmd == nil {
		t.Error("expected tick command to return next tick")
	}
}

func TestSessionSelect(t *testing.T) {
	m := NewModel("")
	m.sessions = []Session{
		{ID: "abcdef1234567890", Hostname: "TARGET"},
	}
	// Press enter to select session
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	um := updated.(Model)
	if um.selectedSession != "abcdef1234567890" {
		t.Errorf("expected session selection, got %q", um.selectedSession)
	}
	if um.view != ViewCommands {
		t.Errorf("expected switch to Commands view after selection, got %d", um.view)
	}
}

func TestCommandInput(t *testing.T) {
	m := NewModel("")
	m.view = ViewCommands
	m.selectedSession = "abcdef1234567890"

	// Press 'i' to activate input
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})
	um := updated.(Model)
	if !um.inputActive {
		t.Error("expected input to be active after pressing 'i'")
	}

	// Press 'esc' to deactivate
	updated, _ = um.Update(tea.KeyMsg{Type: tea.KeyEscape})
	um = updated.(Model)
	if um.inputActive {
		t.Error("expected input to be deactivated after pressing 'esc'")
	}
}

func TestQuit(t *testing.T) {
	m := NewModel("")
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Error("expected quit command")
	}
}
