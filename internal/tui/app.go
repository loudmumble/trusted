// Package tui provides a Bubbletea operator console for the Trusted C2.
package tui

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// View represents the current TUI view.
type View int

const (
	ViewSessions View = iota
	ViewCommands
	ViewListeners
	ViewImplants
	ViewPKI
)

// Session mirrors the C2 session data for the TUI.
type Session struct {
	ID          string
	Hostname    string
	Username    string
	OS          string
	Arch        string
	PID         int
	RemoteAddr  string
	FirstSeen   time.Time
	LastCheckin time.Time
}

// CommandEntry represents a command sent to a session.
type CommandEntry struct {
	ID      string
	Command string
	Args    string
	Queued  time.Time
	Output  string
	Done    bool
}

// ListenerInfo describes a running C2 listener.
type ListenerInfo struct {
	BindAddress string
	Port        int
	Protocol    string
	Running     bool
	Sessions    int
}

// ImplantConfig describes a configured implant.
type ImplantConfig struct {
	ID       string
	Type     string
	C2URL    string
	Interval int
	Jitter   int
}

// PKITemplateInfo describes an ADCS certificate template for TUI display.
type PKITemplateInfo struct {
	Name                    string
	ESCVulns                []string
	ESCScore                int
	EnrolleeSuppliesSubject bool
	AuthenticationEKU       bool
	RequiresManagerApproval bool
}

// commandResult is a command result returned from the C2 /api/results endpoint.
type commandResult struct {
	SessionID string `json:"session_id"`
	CommandID string `json:"command_id"`
	Output    string `json:"output"`
	ExitCode  int    `json:"exit_code"`
}

// c2DataMsg carries live data fetched from the C2 listener.
type c2DataMsg struct {
	Sessions []Session
	Listener *ListenerInfo
	Results  []commandResult
	Err      error
}

// c2CmdResultMsg carries the result of posting a command to the C2.
type c2CmdResultMsg struct {
	LocalID   string // local ID assigned in the TUI (e.g. "cmd-1")
	CommandID string // real command ID returned by the C2
	Err       error
}

// Model is the Bubbletea model for the operator console.
type Model struct {
	c2URL           string
	view            View
	sessions        []Session
	selectedIdx     int
	selectedSession string
	commands        []CommandEntry
	listeners       []ListenerInfo
	implants        []ImplantConfig
	pkiTemplates    []PKITemplateInfo
	cmdInput        textinput.Model
	inputActive     bool
	width           int
	height          int
	statusMsg       string
	lastRefresh     time.Time
}

// newC2Client returns an HTTP client with a short timeout and TLS verification disabled
// for self-signed C2 certificates.
func newC2Client() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // C2 uses self-signed certs
		},
	}
}

// fetchC2Data returns a tea.Cmd that polls the C2 listener for sessions and health.
func fetchC2Data(c2URL string) tea.Cmd {
	return func() tea.Msg {
		client := newC2Client()

		// Fetch sessions
		sessResp, err := client.Get(c2URL + "/api/sessions")
		if err != nil {
			return c2DataMsg{Err: fmt.Errorf("C2 unreachable: %w", err)}
		}
		defer sessResp.Body.Close()
		sessBody, err := io.ReadAll(io.LimitReader(sessResp.Body, 1<<20))
		if err != nil {
			return c2DataMsg{Err: fmt.Errorf("read sessions: %w", err)}
		}

		type apiSession struct {
			ID          string    `json:"id"`
			Hostname    string    `json:"hostname"`
			Username    string    `json:"username"`
			OS          string    `json:"os"`
			Arch        string    `json:"arch"`
			PID         int       `json:"pid"`
			RemoteAddr  string    `json:"remote_addr"`
			FirstSeen   time.Time `json:"first_seen"`
			LastCheckin time.Time `json:"last_checkin"`
		}
		var raw []apiSession
		if err := json.Unmarshal(sessBody, &raw); err != nil {
			return c2DataMsg{Err: fmt.Errorf("parse sessions: %w", err)}
		}
		sessions := make([]Session, len(raw))
		for i, s := range raw {
			sessions[i] = Session{
				ID:          s.ID,
				Hostname:    s.Hostname,
				Username:    s.Username,
				OS:          s.OS,
				Arch:        s.Arch,
				PID:         s.PID,
				RemoteAddr:  s.RemoteAddr,
				FirstSeen:   s.FirstSeen,
				LastCheckin: s.LastCheckin,
			}
		}

		// Fetch health
		healthResp, err := client.Get(c2URL + "/health")
		if err != nil {
			return c2DataMsg{Sessions: sessions, Err: fmt.Errorf("health check failed: %w", err)}
		}
		defer healthResp.Body.Close()
		healthBody, err := io.ReadAll(io.LimitReader(healthResp.Body, 1<<16))
		if err != nil {
			return c2DataMsg{Sessions: sessions, Err: fmt.Errorf("read health: %w", err)}
		}
		var health struct {
			Status   string `json:"status"`
			Sessions int    `json:"sessions"`
		}
		if err := json.Unmarshal(healthBody, &health); err != nil {
			return c2DataMsg{Sessions: sessions, Err: fmt.Errorf("parse health: %w", err)}
		}

		// Derive protocol from URL
		proto := "http"
		if strings.HasPrefix(c2URL, "https") {
			proto = "https"
		}
		// Extract host:port for display
		bind := strings.TrimPrefix(strings.TrimPrefix(c2URL, "https://"), "http://")

		listener := &ListenerInfo{
			BindAddress: bind,
			Protocol:    proto,
			Running:     health.Status == "ok",
			Sessions:    health.Sessions,
		}

		// Fetch command results
		var results []commandResult
		resultsResp, err := client.Get(c2URL + "/api/results")
		if err == nil {
			defer resultsResp.Body.Close()
			resultsBody, err := io.ReadAll(io.LimitReader(resultsResp.Body, 1<<20))
			if err == nil {
				json.Unmarshal(resultsBody, &results)
			}
		}

		return c2DataMsg{Sessions: sessions, Listener: listener, Results: results}
	}
}

// postC2Command sends a command to the C2 for the given session.
func postC2Command(c2URL, sessionID, command, localID string) tea.Cmd {
	return func() tea.Msg {
		client := newC2Client()
		payload, _ := json.Marshal(map[string]string{
			"session_id": sessionID,
			"command":    command,
		})
		resp, err := client.Post(c2URL+"/api/command", "application/json", bytes.NewReader(payload))
		if err != nil {
			return c2CmdResultMsg{LocalID: localID, Err: fmt.Errorf("post command: %w", err)}
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
			return c2CmdResultMsg{LocalID: localID, Err: fmt.Errorf("command rejected (%d): %s", resp.StatusCode, string(body))}
		}
		var result struct {
			CommandID string `json:"command_id"`
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		json.Unmarshal(body, &result)
		return c2CmdResultMsg{LocalID: localID, CommandID: result.CommandID}
	}
}

// NewModel creates a new TUI model. Starts empty; populated by live C2 data.
// Pass a non-empty c2URL to enable live polling from the C2 listener.
func NewModel(c2URL string) Model {
	ti := textinput.New()
	ti.Placeholder = "Enter command..."
	ti.CharLimit = 256
	ti.Width = 60

	return Model{
		c2URL:       c2URL,
		view:        ViewSessions,
		sessions:    []Session{},
		listeners:   []ListenerInfo{},
		implants:    []ImplantConfig{},
		cmdInput:    ti,
		lastRefresh: time.Now(),
		statusMsg:   "Ready",
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, tickCmd())
}

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		m.lastRefresh = time.Now()
		if m.c2URL != "" {
			return m, tea.Batch(tickCmd(), fetchC2Data(m.c2URL))
		}
		return m, tickCmd()

	case c2DataMsg:
		// Always update sessions if present (even on partial errors like health check failure)
		if msg.Sessions != nil {
			m.sessions = msg.Sessions
		}
		if msg.Listener != nil {
			m.listeners = []ListenerInfo{*msg.Listener}
		}
		// Match results to pending commands
		for _, r := range msg.Results {
			for i, cmd := range m.commands {
				if cmd.ID == r.CommandID && !cmd.Done {
					m.commands[i].Done = true
					m.commands[i].Output = r.Output
				}
			}
		}
		if msg.Err != nil {
			m.statusMsg = fmt.Sprintf("C2: %s", msg.Err)
		} else {
			m.statusMsg = fmt.Sprintf("Connected — %d sessions", len(m.sessions))
		}
		return m, nil

	case c2CmdResultMsg:
		if msg.Err != nil {
			m.statusMsg = fmt.Sprintf("Cmd error: %s", msg.Err)
		} else if msg.CommandID != "" {
			// Remap local ID to real C2 command ID so results can be matched
			for i, cmd := range m.commands {
				if cmd.ID == msg.LocalID {
					m.commands[i].ID = msg.CommandID
					break
				}
			}
		}
		return m, nil

	case tea.KeyMsg:
		if m.inputActive {
			switch msg.String() {
			case "enter":
				cmdText := m.cmdInput.Value()
				if cmdText != "" && m.selectedSession != "" {
					localID := fmt.Sprintf("cmd-%d", len(m.commands)+1)
					m.commands = append(m.commands, CommandEntry{
						ID:      localID,
						Command: cmdText,
						Queued:  time.Now(),
					})
					sid := m.selectedSession
					if len(sid) > 8 {
						sid = sid[:8]
					}
					m.statusMsg = fmt.Sprintf("Queued: %s → %s", cmdText, sid)
					m.cmdInput.Reset()
					if m.c2URL != "" {
						return m, postC2Command(m.c2URL, m.selectedSession, cmdText, localID)
					}
				} else {
					m.cmdInput.Reset()
				}
				return m, nil
			case "esc":
				m.inputActive = false
				m.cmdInput.Blur()
				return m, nil
			default:
				var cmd tea.Cmd
				m.cmdInput, cmd = m.cmdInput.Update(msg)
				return m, cmd
			}
		}

		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "1":
			m.view = ViewSessions
			m.statusMsg = "Sessions"
		case "2":
			m.view = ViewCommands
			m.statusMsg = "Commands"
		case "3":
			m.view = ViewListeners
			m.statusMsg = "Listeners"
		case "4":
			m.view = ViewImplants
			m.statusMsg = "Implants"
		case "5":
			m.view = ViewPKI
			m.statusMsg = "PKI Templates"
		case "j", "down":
			m.moveSelection(1)
		case "k", "up":
			m.moveSelection(-1)
		case "enter":
			if m.view == ViewSessions && len(m.sessions) > 0 {
				m.selectedSession = m.sessions[m.selectedIdx].ID
				m.view = ViewCommands
				m.statusMsg = fmt.Sprintf("Session: %s", m.selectedSession[:8])
			}
		case "i":
			if m.view == ViewCommands {
				m.inputActive = true
				m.cmdInput.Focus()
				cmds = append(cmds, textinput.Blink)
			}
		case "tab":
			m.view = (m.view + 1) % 5
		}
	}

	return m, tea.Batch(cmds...)
}

func (m *Model) moveSelection(delta int) {
	max := 0
	switch m.view {
	case ViewSessions:
		max = len(m.sessions)
	case ViewCommands:
		max = len(m.commands)
	case ViewListeners:
		max = len(m.listeners)
	case ViewImplants:
		max = len(m.implants)
	case ViewPKI:
		max = len(m.pkiTemplates)
	}
	if max == 0 {
		return
	}
	m.selectedIdx += delta
	if m.selectedIdx < 0 {
		m.selectedIdx = 0
	}
	if m.selectedIdx >= max {
		m.selectedIdx = max - 1
	}
}

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FF6600")).
			Background(lipgloss.Color("#1a1a2e")).
			Padding(0, 1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FF88"))

	selectedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#000000")).
			Background(lipgloss.Color("#FF6600"))

	normalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CCCCCC"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666666"))

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF6600")).
			Bold(true)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#FF6600")).
			Padding(0, 1)
)

func (m Model) View() string {
	var b strings.Builder

	// Header
	banner := titleStyle.Render(" TRUSTED C2 CONSOLE ")
	tabs := m.renderTabs()
	b.WriteString(banner + "  " + tabs + "\n\n")

	// Main content
	switch m.view {
	case ViewSessions:
		b.WriteString(m.renderSessions())
	case ViewCommands:
		b.WriteString(m.renderCommands())
	case ViewListeners:
		b.WriteString(m.renderListeners())
	case ViewImplants:
		b.WriteString(m.renderImplants())
	case ViewPKI:
		b.WriteString(m.renderPKI())
	}

	// Status bar
	b.WriteString("\n")
	status := fmt.Sprintf(" %s | %s | q:quit tab:switch 1-5:views",
		statusStyle.Render(m.statusMsg),
		dimStyle.Render(m.lastRefresh.Format("15:04:05")))
	b.WriteString(status)

	return b.String()
}

func (m Model) renderTabs() string {
	tabs := []string{"[1]Sessions", "[2]Commands", "[3]Listeners", "[4]Implants", "[5]PKI"}
	var parts []string
	for i, t := range tabs {
		if View(i) == m.view {
			parts = append(parts, headerStyle.Render(t))
		} else {
			parts = append(parts, dimStyle.Render(t))
		}
	}
	return strings.Join(parts, " | ")
}

func (m Model) renderSessions() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render("Active Sessions") + "\n\n")

	if len(m.sessions) == 0 {
		b.WriteString(dimStyle.Render("  No active sessions. Waiting for implant check-ins...\n"))
		b.WriteString(dimStyle.Render("  Start a listener: trusted c2 --port 8443 --protocol https\n"))
		return b.String()
	}

	// Table header
	hdr := fmt.Sprintf("  %-10s %-15s %-12s %-10s %-18s %-20s",
		"ID", "HOSTNAME", "USER", "OS", "IP", "LAST SEEN")
	b.WriteString(headerStyle.Render(hdr) + "\n")
	b.WriteString(dimStyle.Render(strings.Repeat("─", 90)) + "\n")

	for i, s := range m.sessions {
		id := s.ID
		if len(id) > 8 {
			id = id[:8]
		}
		ago := time.Since(s.LastCheckin).Round(time.Second)
		line := fmt.Sprintf("  %-10s %-15s %-12s %-10s %-18s %s ago",
			id, s.Hostname, s.Username, s.OS, s.RemoteAddr, ago)
		if i == m.selectedIdx {
			b.WriteString(selectedStyle.Render(line) + "\n")
		} else {
			b.WriteString(normalStyle.Render(line) + "\n")
		}
	}

	b.WriteString("\n" + dimStyle.Render("  j/k:navigate  enter:select  "))
	return b.String()
}

func (m Model) renderCommands() string {
	var b strings.Builder

	if m.selectedSession != "" {
		sid := m.selectedSession
		if len(sid) > 8 {
			sid = sid[:8]
		}
		b.WriteString(headerStyle.Render(fmt.Sprintf("Commands → Session %s", sid)) + "\n\n")
	} else {
		b.WriteString(headerStyle.Render("Commands (no session selected)") + "\n\n")
	}

	if len(m.commands) == 0 {
		b.WriteString(dimStyle.Render("  No commands yet. Press 'i' to enter a command.\n"))
	} else {
		for i, c := range m.commands {
			status := "⏳"
			if c.Done {
				status = "✓"
			}
			line := fmt.Sprintf("  %s %-10s %s", status, c.ID, c.Command)
			if i == m.selectedIdx {
				b.WriteString(selectedStyle.Render(line) + "\n")
			} else {
				b.WriteString(normalStyle.Render(line) + "\n")
			}
			if c.Output != "" {
				b.WriteString(dimStyle.Render("    → "+c.Output) + "\n")
			}
		}
	}

	if m.inputActive {
		b.WriteString("\n  " + m.cmdInput.View())
	} else {
		b.WriteString("\n" + dimStyle.Render("  i:input command  esc:back"))
	}

	return b.String()
}

func (m Model) renderListeners() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render("Active Listeners") + "\n\n")

	if len(m.listeners) == 0 {
		b.WriteString(dimStyle.Render("  No active listeners.\n"))
		return b.String()
	}

	hdr := fmt.Sprintf("  %-18s %-8s %-10s %-10s",
		"BIND", "PORT", "PROTOCOL", "SESSIONS")
	b.WriteString(headerStyle.Render(hdr) + "\n")
	b.WriteString(dimStyle.Render(strings.Repeat("─", 50)) + "\n")

	for i, l := range m.listeners {
		status := "●"
		if !l.Running {
			status = "○"
		}
		line := fmt.Sprintf("  %s %-15s %-8d %-10s %-10d",
			status, l.BindAddress, l.Port, l.Protocol, l.Sessions)
		if i == m.selectedIdx {
			b.WriteString(selectedStyle.Render(line) + "\n")
		} else {
			b.WriteString(normalStyle.Render(line) + "\n")
		}
	}

	return b.String()
}

func (m Model) renderImplants() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render("Implant Configurations") + "\n\n")

	if len(m.implants) == 0 {
		b.WriteString(dimStyle.Render("  No implant configurations.\n"))
		return b.String()
	}

	hdr := fmt.Sprintf("  %-18s %-15s %-35s %-8s %-8s",
		"ID", "TYPE", "C2 URL", "INTERVAL", "JITTER")
	b.WriteString(headerStyle.Render(hdr) + "\n")
	b.WriteString(dimStyle.Render(strings.Repeat("─", 90)) + "\n")

	for i, imp := range m.implants {
		line := fmt.Sprintf("  %-18s %-15s %-35s %-8ds %-8d%%",
			imp.ID, imp.Type, imp.C2URL, imp.Interval, imp.Jitter)
		if i == m.selectedIdx {
			b.WriteString(selectedStyle.Render(line) + "\n")
		} else {
			b.WriteString(normalStyle.Render(line) + "\n")
		}
	}

	return b.String()
}

func (m Model) renderPKI() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render(fmt.Sprintf("PKI / ADCS Templates — %d templates", len(m.pkiTemplates))) + "\n\n")

	if len(m.pkiTemplates) == 0 {
		b.WriteString(dimStyle.Render("  No templates enumerated yet.\n"))
		b.WriteString(dimStyle.Render("  Run: trusted pki --enum --target-dc <dc> --domain <domain>\n"))
		return b.String()
	}

	hdr := fmt.Sprintf("  %-30s %-20s %-8s %-8s %-8s %-10s",
		"TEMPLATE", "ESC VULNS", "SCORE", "ESS", "AUTH", "APPROVAL")
	b.WriteString(headerStyle.Render(hdr) + "\n")
	b.WriteString(dimStyle.Render(strings.Repeat("─", 95)) + "\n")

	for i, tmpl := range m.pkiTemplates {
		vulns := "none"
		if len(tmpl.ESCVulns) > 0 {
			vulns = strings.Join(tmpl.ESCVulns, ",")
		}
		ess := "no"
		if tmpl.EnrolleeSuppliesSubject {
			ess = "YES"
		}
		auth := "no"
		if tmpl.AuthenticationEKU {
			auth = "YES"
		}
		approval := "no"
		if tmpl.RequiresManagerApproval {
			approval = "YES"
		}
		line := fmt.Sprintf("  %-30s %-20s %-8d %-8s %-8s %-10s",
			tmpl.Name, vulns, tmpl.ESCScore, ess, auth, approval)
		if i == m.selectedIdx {
			b.WriteString(selectedStyle.Render(line) + "\n")
		} else if tmpl.ESCScore >= 10 {
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Bold(true).Render(line) + "\n")
		} else if tmpl.ESCScore > 0 {
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFAA00")).Render(line) + "\n")
		} else {
			b.WriteString(normalStyle.Render(line) + "\n")
		}
	}

	b.WriteString("\n" + dimStyle.Render("  ESS=Enrollee Supplies Subject  AUTH=Authentication EKU"))
	return b.String()
}
