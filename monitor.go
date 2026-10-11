package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	styleTitle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	styleHeader  = lipgloss.NewStyle().Bold(true)
	styleOnline  = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleOffline = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	styleUnknown = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styleDim     = lipgloss.NewStyle().Faint(true)
)

type peerStatus int

const (
	statusUnknown peerStatus = iota
	statusOnline
	statusOffline
)

type peerInfo struct {
	Name    string
	IP      string
	Port    int
	Status  peerStatus
	Ping    time.Duration
	LastTry time.Time
}

type tickMsg time.Time

type model struct {
	peers    []peerInfo
	name     string
	width    int
	height   int
	quitting bool
}

func (m model) Init() tea.Cmd {
	return tea.Batch(tickCmd(), tea.EnterAltScreen)
}

func tickCmd() tea.Cmd {
	return tea.Tick(3*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "r":
			m.pingAll()
			return m, nil
		}

	case tickMsg:
		m.pingAll()
		return m, tickCmd()
	}

	return m, nil
}

func (m model) View() string {
	if m.quitting {
		return ""
	}

	online := 0
	for _, p := range m.peers {
		if p.Status == statusOnline {
			online++
		}
	}

	var b strings.Builder

	// Title
	b.WriteString(styleTitle.Render("  Network Beacons Monitor"))
	b.WriteString("\n")

	// Info line
	info := fmt.Sprintf("  Узел: %s  |  Пиров: %d (онлайн: %d)", m.name, len(m.peers), online)
	b.WriteString(info)
	b.WriteString("\n\n")

	// Table header
	b.WriteString(styleHeader.Render("  Имя"))
	b.WriteString(strings.Repeat(" ", max(1, 18-4)))
	b.WriteString(styleHeader.Render("IP"))
	b.WriteString(strings.Repeat(" ", max(1, 16-2)))
	b.WriteString(styleHeader.Render("Статус"))
	b.WriteString(strings.Repeat(" ", max(1, 10-6)))
	b.WriteString(styleHeader.Render("Пинг"))
	b.WriteString("\n")
	b.WriteString(styleDim.Render(strings.Repeat("─", 56)))
	b.WriteString("\n")

	// Rows
	for _, p := range m.peers {
		name := truncate(p.Name, 16)
		ip := p.IP
		if ip == "" {
			ip = "—"
		}

		var statusStr string
		switch p.Status {
		case statusOnline:
			statusStr = styleOnline.Render("ONLINE")
		case statusOffline:
			statusStr = styleOffline.Render("OFFLINE")
		default:
			statusStr = styleUnknown.Render("???")
		}

		pingStr := "—"
		if p.Ping > 0 {
			pingStr = fmt.Sprintf("%dms", p.Ping.Milliseconds())
		}

		b.WriteString(fmt.Sprintf("  %-16s %-15s %-17s %s\n", name, ip, statusStr, pingStr))
	}

	b.WriteString("\n")
	b.WriteString(styleDim.Render("  [q] Выход  [r] Ping всех"))
	b.WriteString("\n")

	return b.String()
}

func (m *model) pingAll() {
	var wg sync.WaitGroup
	for i := range m.peers {
		if m.peers[i].IP == "" {
			continue
		}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			p := &m.peers[idx]
			start := time.Now()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", p.IP, p.Port), 3*time.Second)
			latency := time.Since(start)

			if err != nil {
				p.Status = statusOffline
				p.Ping = 0
			} else {
				conn.Close()
				p.Status = statusOnline
				p.Ping = latency
			}
			p.LastTry = time.Now()
		}(i)
	}
	wg.Wait()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func loadPeers(cfg *Config, ts *TrustStore) []peerInfo {
	var peers []peerInfo

	// Только из TrustStore — имена из сертификатов
	if ts != nil {
		for _, cert := range ts.getTrustedCerts() {
			cn := cert.Subject.CommonName
			if cn == "Root CA" || cn == "" || cn == cfg.NodeName {
				continue
			}
			peers = append(peers, peerInfo{Name: cn, Port: cfg.TLSPort})
		}
	}

	return peers
}

func RunMonitor(cfg *Config) error {
	var ts *TrustStore
	_, _, caPath := cfg.BeaconPaths()
	crlPath := cfg.DataDir + "/ca/crl.pem"
	if _, e := os.Stat(caPath); e == nil {
		ts, _ = NewTrustStore(caPath, crlPath)
	}

	peers := loadPeers(cfg, ts)

	m := model{
		peers: peers,
		name:  cfg.NodeName,
	}

	log.SetOutput(os.Stderr)
	log.Printf("[Monitor] %s: %d пиров", cfg.NodeName, len(peers))

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
