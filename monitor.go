package main

import (
	"bufio"
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
		return "???"
	}
}

type PeerInfo struct {
	Name    string
	IP      string
	Port    int
	Status  PeerStatus
	Ping    time.Duration
	LastTry time.Time
}

type Monitor struct {
	mu       sync.Mutex
	peers    []*PeerInfo
	cfg      *Config
	stopCh   chan struct{}
	stopOnce sync.Once
	name     string
	uptime   time.Time
}

func NewMonitor(cfg *Config, ts *TrustStore) *Monitor {
	m := &Monitor{
		cfg:    cfg,
		peers:  make([]*PeerInfo, 0),
		stopCh: make(chan struct{}),
		name:   cfg.NodeName,
		uptime: time.Now(),
	}
	m.loadFromTrustStore(ts)
	m.loadPeersFile()
	return m
}

func (m *Monitor) loadFromTrustStore(ts *TrustStore) {
	if ts == nil {
		return
	}
	for _, cert := range ts.getTrustedCerts() {
		cn := cert.Subject.CommonName
		if cn == "Root CA" || cn == "" || cn == m.name {
			continue
		}
		m.peers = append(m.peers, &PeerInfo{
			Name: cn,
			Port: m.cfg.TLSPort,
		})
	}
}

func (m *Monitor) loadPeersFile() {
	f, err := os.Open(m.cfg.DataDir + "/peers.txt")
	if err != nil {
		return
	}
	defer f.Close()

	known := make(map[string]bool)
	for _, p := range m.peers {
		known[p.Name] = true
	}

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
		name, ip := parts[0], parts[1]

		if known[name] {
			for _, p := range m.peers {
				if p.Name == name {
					p.IP = ip
					p.Port = m.cfg.TLSPort
				}
			}
		} else {
			m.peers = append(m.peers, &PeerInfo{
				Name: name,
				IP:   ip,
				Port: m.cfg.TLSPort,
			})
		}
	}
}

func (m *Monitor) Stop() {
	m.stopOnce.Do(func() { close(m.stopCh) })
}

func (m *Monitor) Run() error {
	old, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("raw mode: %w", err)
	}
	defer term.Restore(int(os.Stdin.Fd()), old)

	go m.pingLoop()
	go m.inputLoop()

	m.render()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

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

	fmt.Print("\033[H\033[2J")

	online := 0
	for _, p := range m.peers {
		if p.Status == StatusOnline {
			online++
		}
	}

	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Printf("║  Network Beacons Monitor                               ║\n")
	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Узел: %-10s  Пиров: %d (онлайн: %d)              ║\n", m.name, len(m.peers), online)
	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Println("║  Имя              IP               Статус    Пинг      ║")
	fmt.Println("║  ──────────────── ──────────────── ──────── ──────────  ║")

	if len(m.peers) == 0 {
		fmt.Println("║  (нет пиров)                                           ║")
	}

	for _, p := range m.peers {
		name := p.Name
		if len(name) > 16 {
			name = name[:13] + "..."
		}
		ip := p.IP
		if ip == "" {
			ip = "—"
		}
		status := p.Status.String()
		ping := "—"
		if p.Ping > 0 {
			ping = fmt.Sprintf("%dms", p.Ping.Milliseconds())
		}
		fmt.Printf("║  %-16s %-15s %-8s %-8s ║\n", name, ip, status, ping)
	}

	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Println("║  [Q] Выход  [R] Ping всех                              ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
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
		if buf[0] == 'r' || buf[0] == 'R' {
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
	list := make([]*PeerInfo, len(m.peers))
	copy(list, m.peers)
	m.mu.Unlock()

	var wg sync.WaitGroup
	for _, p := range list {
		if p.IP == "" {
			continue
		}
		wg.Add(1)
		go func(peer *PeerInfo) {
			defer wg.Done()
			start := time.Now()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", peer.IP, peer.Port), 3*time.Second)
			latency := time.Since(start)

			m.mu.Lock()
			defer m.mu.Unlock()
			peer.LastTry = time.Now()
			if err != nil {
				peer.Status = StatusOffline
				peer.Ping = 0
			} else {
				conn.Close()
				peer.Status = StatusOnline
				peer.Ping = latency
			}
		}(p)
	}
	wg.Wait()
}

func RunMonitor(cfg *Config) error {
	var ts *TrustStore
	_, _, caPath := cfg.BeaconPaths()
	crlPath := cfg.DataDir + "/ca/crl.pem"
	if _, e := os.Stat(caPath); e == nil {
		ts, _ = NewTrustStore(caPath, crlPath)
	}

	monitor := NewMonitor(cfg, ts)
	defer monitor.Stop()

	log.SetOutput(os.Stderr)
	log.Printf("[Monitor] %s: %d пиров", cfg.NodeName, len(monitor.peers))

	return monitor.Run()
}
