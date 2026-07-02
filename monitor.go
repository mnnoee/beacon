package main

import (
	"bufio"
	"crypto/ed25519"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

type PeerStatus int

const (
	StatusUnknown PeerStatus = iota
	StatusOnline
	StatusOffline
)

func (s PeerStatus) String() string {
	switch s {
	case StatusOnline:
		return "ONLINE"
	case StatusOffline:
		return "OFFLINE"
	default:
		return "UNKNOWN"
	}
}

type PeerInfo struct {
	Name      string
	IP        string
	TLSPort   int
	Status    PeerStatus
	Latency   time.Duration
	LastSeen  time.Time
	FirstSeen time.Time
}

type Monitor struct {
	mu    sync.Mutex
	peers []*PeerInfo

	cfg        *Config
	stopCh     chan struct{}
	stopOnce   sync.Once
	nodeName   string
	uptime     time.Time
	trustStore *TrustStore
}

func NewMonitor(cfg *Config, ts *TrustStore) *Monitor {
	m := &Monitor{
		peers:      make([]*PeerInfo, 0),
		cfg:        cfg,
		stopCh:     make(chan struct{}),
		nodeName:   cfg.NodeName,
		uptime:     time.Now(),
		trustStore: ts,
	}
	m.loadKnownPeers()
	return m
}

// loadKnownPeers загружает пиров из TrustStore + peers-файла.
func (m *Monitor) loadKnownPeers() {
	// 1. Из TrustStore (только имена, без IP)
	if m.trustStore != nil {
		for _, cert := range m.trustStore.getTrustedCerts() {
			cn := cert.Subject.CommonName
			if cn == "Root CA" || cn == "" || cn == m.nodeName {
				continue
			}
			m.peers = append(m.peers, &PeerInfo{
				Name:      cn,
				TLSPort:   m.cfg.TLSPort,
				Status:    StatusUnknown,
				FirstSeen: time.Now(),
			})
		}
	}

	// 2. Из файла peers.txt (имя IP)
	m.loadPeersFile()
}

// loadPeersFile загружает пиры из файла peers.txt
// Формат: <имя> <ip> (по одной строке)
func (m *Monitor) loadPeersFile() {
	peersFile := m.cfg.DataDir + "/peers.txt"
	f, err := os.Open(peersFile)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		name := parts[0]
		ip := parts[1]

		// Обновляем существующий пир или добавляем нового
		found := false
		for _, p := range m.peers {
			if p.Name == name {
				p.IP = ip
				p.TLSPort = m.cfg.TLSPort
				found = true
				break
			}
		}
		if !found {
			m.peers = append(m.peers, &PeerInfo{
				Name:      name,
				IP:        ip,
				TLSPort:   m.cfg.TLSPort,
				Status:    StatusUnknown,
				FirstSeen: time.Now(),
			})
		}
	}
}

func (m *Monitor) Stop() {
	m.stopOnce.Do(func() { close(m.stopCh) })
}

func (m *Monitor) Run() error {
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("raw mode: %w", err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	go m.pingLoop()
	go m.inputLoop()

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	m.render()

	for {
		select {
		case <-m.stopCh:
			return nil
		case <-ticker.C:
			m.pingAll()
			m.render()
		}
	}
}

func (m *Monitor) render() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Очищаем экран
	fmt.Print("\033[2J\033[H")

	w := 62 // ширина внутренней области

	uptime := time.Since(m.uptime).Truncate(time.Second)
	online := 0
	for _, p := range m.peers {
		if p.Status == StatusOnline {
			online++
		}
	}

	// Верхняя рамка
	fmt.Printf("\033[1;36m┌%s┐\033[0m\n", repeat("─", w))
	fmt.Printf("\033[1;36m│\033[0m \033[1;37mNetwork Beacons Monitor\033[0m%s\033[1;36m│\033[0m\n", repeat(" ", w-25))
	fmt.Printf("\033[1;36m├%s┤\033[0m\n", repeat("─", w))
	fmt.Printf("\033[1;36m│\033[0m Узел: \033[1;33m%-14s\033[0m  Аптайм: \033[1;32m%-8s\033[0m  %s\033[1;36m│\033[0m\n",
		m.nodeName, uptime, pad("", w-38))
	fmt.Printf("\033[1;36m│\033[0m Пиров: \033[1;33m%d\033[0m (онлайн: \033[1;32m%d\033[0m)%s\033[1;36m│\033[0m\n",
		len(m.peers), online, pad("", w-22-len(fmt.Sprintf("%d%d", len(m.peers), online))))
	fmt.Printf("\033[1;36m├%s┤\033[0m\n", repeat("─", w))

	// Заголовок таблицы
	fmt.Printf("\033[1;36m│\033[0m \033[1m%-16s %-15s %-10s %-6s %-10s\033[0m %s\033[1;36m│\033[0m\n",
		"ИМЯ", "IP", "СТАТУС", "ПИНГ", "ПОСЛЕДНИЙ", pad("", w-55))
	fmt.Printf("\033[1;36m│\033[0m %s %s\033[1;36m│\033[0m\n", repeat("─", 54), pad("", w-55))

	if len(m.peers) == 0 {
		fmt.Printf("\033[1;36m│\033[0m \033[2m%s\033[0m %s\033[1;36m│\033[0m\n", pad("нет известных пиров", 54), pad("", w-55))
	}

	for _, peer := range m.peers {
		color := "\033[33m"
		if peer.Status == StatusOnline {
			color = "\033[32m"
		} else if peer.Status == StatusOffline {
			color = "\033[31m"
		}

		latency := "—"
		if peer.Latency > 0 {
			latency = fmt.Sprintf("%dms", peer.Latency.Milliseconds())
		}

		lastSeen := "—"
		if !peer.LastSeen.IsZero() {
			lastSeen = fmt.Sprintf("%dsназад", int(time.Since(peer.LastSeen).Seconds()))
		}

		name := truncate(peer.Name, 16)
		ip := truncate(peer.IP, 15)
		if ip == "" {
			ip = "—"
		}

		fmt.Printf("\033[1;36m│\033[0m %-16s %-15s %s%-10s\033[0m %-6s %-10s %s\033[1;36m│\033[0m\n",
			name, ip, color, peer.Status, latency, lastSeen, pad("", w-55))
	}

	fmt.Printf("\033[1;36m├%s┤\033[0m\n", repeat("─", w))
	fmt.Printf("\033[1;36m│\033[0m \033[2m[Q] Выход   [R] Ping всех пиров\033[0m%s\033[1;36m│\033[0m\n", pad("", w-34))
	fmt.Printf("\033[1;36m└%s┘\033[0m\n", repeat("─", w))
}

func (m *Monitor) inputLoop() {
	buf := make([]byte, 1)
	for {
		select {
		case <-m.stopCh:
			return
		default:
		}
		os.Stdin.Read(buf)
		if buf[0] == 'q' || buf[0] == 'Q' || buf[0] == 3 {
			m.Stop()
			return
		}
		if buf[0] == 'r' || buf[0] == 'R' || buf[0] == 'p' || buf[0] == 'P' {
			m.pingAll()
			m.render()
		}
	}
}

func (m *Monitor) pingLoop() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.pingAll()
			m.render()
		}
	}
}

func (m *Monitor) pingAll() {
	m.mu.Lock()
	peers := make([]*PeerInfo, len(m.peers))
	copy(peers, m.peers)
	m.mu.Unlock()

	var wg sync.WaitGroup
	for _, p := range peers {
		if p.IP == "" {
			continue
		}
		wg.Add(1)
		go func(peer *PeerInfo) {
			defer wg.Done()
			start := time.Now()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", peer.IP, peer.TLSPort), 3*time.Second)
			latency := time.Since(start)

			m.mu.Lock()
			defer m.mu.Unlock()
			if err != nil {
				peer.Status = StatusOffline
				peer.Latency = 0
			} else {
				conn.Close()
				peer.Status = StatusOnline
				peer.Latency = latency
				peer.LastSeen = time.Now()
			}
		}(p)
	}
	wg.Wait()
}

func repeat(s string, n int) string {
	if n <= 0 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(s)
	}
	return b.String()
}

func pad(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + repeat(" ", width-len(s))
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func RunMonitor(cfg *Config) error {
	keyPath, _, _ := cfg.BeaconPaths()
	nodeName := cfg.NodeName

	var ts *TrustStore
	_, _, caPath := cfg.BeaconPaths()
	crlPath := cfg.DataDir + "/ca/crl.pem"
	if _, statErr := os.Stat(caPath); statErr == nil {
		ts, _ = NewTrustStore(caPath, crlPath)
	}

	monitor := NewMonitor(cfg, ts)

	// Определяем nodeID
	edKey, err := loadEd25519Key(keyPath)
	if err == nil {
		pub := edKey.Public().(ed25519.PublicKey)
		_ = [16]byte(pub[:16])
	}
	_ = nodeName

	log.SetOutput(os.Stderr)
	log.Printf("[Monitor] запуск: %s (пиров: %d)", cfg.NodeName, len(monitor.peers))
	log.Printf("[Monitor] для добавления пиров создайте %s/peers.txt", cfg.DataDir)
	log.Printf("[Monitor] формат: <имя> <ip>")

	return monitor.Run()
}
