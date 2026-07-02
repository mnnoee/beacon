package main

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// PeerStatus — статус пира.
type PeerStatus int

const (
	StatusUnknown  PeerStatus = iota
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

// PeerInfo — информация о пире.
type PeerInfo struct {
	Name      string
	ID        [16]byte
	IP        string
	TLSPort   int
	Status    PeerStatus
	Latency   time.Duration
	LastSeen  time.Time
	FirstSeen time.Time
	ConnCount int
}

// Monitor — TUI-монитор.
type Monitor struct {
	mu    sync.RWMutex
	peers map[[16]byte]*PeerInfo

	cfg        *Config
	stopCh     chan struct{}
	stopOnce   sync.Once
	refresh    chan struct{}
	nodeName   string
	nodeID     [16]byte
	uptime     time.Time
	trustStore *TrustStore
}

// NewMonitor создаёт монитор.
func NewMonitor(cfg *Config, nodeID [16]byte, ts *TrustStore) *Monitor {
	m := &Monitor{
		peers:      make(map[[16]byte]*PeerInfo),
		cfg:        cfg,
		stopCh:     make(chan struct{}),
		refresh:    make(chan struct{}, 1),
		nodeName:   cfg.NodeName,
		nodeID:     nodeID,
		uptime:     time.Now(),
		trustStore: ts,
	}
	// Загружаем известных пиров из TrustStore
	m.loadKnownPeers()
	return m
}

// loadKnownPeers загружает список известных пиров из TrustStore.
// Это позволяет видеть все маячки даже если UDP discovery не работает.
func (m *Monitor) loadKnownPeers() {
	if m.trustStore == nil {
		return
	}

	for _, cert := range m.trustStore.getTrustedCerts() {
		if cert.Subject.CommonName == "Root CA" || cert.Subject.CommonName == "" {
			continue
		}
		// Пропускаем себя
		if cert.Subject.CommonName == m.nodeName {
			continue
		}

		var id [16]byte
		if len(cert.SubjectKeyId) >= 16 {
			copy(id[:], cert.SubjectKeyId[:16])
		} else {
			copy(id[:], cert.SerialNumber.Bytes()[:16])
		}

		peer := &PeerInfo{
			Name:      cert.Subject.CommonName,
			ID:        id,
			TLSPort:   m.cfg.TLSPort,
			Status:    StatusUnknown,
			FirstSeen: time.Now(),
		}
		m.peers[id] = peer
	}
}

// AddPeer добавляет пира из UDP discovery.
func (m *Monitor) AddPeer(id [16]byte, addr *net.UDPAddr, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	peer, exists := m.peers[id]
	if !exists {
		peer = &PeerInfo{
			Name:      name,
			ID:        id,
			IP:        addr.IP.String(),
			TLSPort:   m.cfg.TLSPort,
			Status:    StatusUnknown,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		m.peers[id] = peer
	} else {
		peer.IP = addr.IP.String()
		peer.LastSeen = time.Now()
		if name != "" {
			peer.Name = name
		}
	}

	select {
	case m.refresh <- struct{}{}:
	default:
	}
}

// Stop останавливает монитор (безопасно для повторных вызовов).
func (m *Monitor) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})
}

// Run запускает TUI.
func (m *Monitor) Run() error {
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("raw mode: %w", err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	fmt.Print("\033[2J\033[H\033[?25l")
	defer fmt.Print("\033[2J\033[H\033[?25h")

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
			m.render()
		case <-m.refresh:
			m.render()
		}
	}
}

// render отрисовывает TUI.
func (m *Monitor) render() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var b strings.Builder
	b.WriteString("\033[2J\033[H")

	// Заголовок
	uptime := time.Since(m.uptime).Truncate(time.Second)
	peerCount := len(m.peers)
	onlineCount := 0
	for _, p := range m.peers {
		if p.Status == StatusOnline {
			onlineCount++
		}
	}

	b.WriteString("\033[1;36m┌──────────────────────────────────────────────────────────────┐\033[0m\n")
	b.WriteString(fmt.Sprintf("\033[1;36m│\033[0m \033[1;37m%-20s\033[0m  Узел: \033[1;33m%-16s\033[0m \033[1;36m│\033[0m\n", "Network Beacons", m.nodeName))
	b.WriteString(fmt.Sprintf("\033[1;36m│\033[0m Аптайм: \033[1;32m%-10s\033[0m  Пиров: \033[1;33m%d\033[0m (онлайн: \033[1;32m%d\033[0m)      \033[1;36m│\033[0m\n", uptime, peerCount, onlineCount))
	b.WriteString("\033[1;36m├──────────────────────────────────────────────────────────────┤\033[0m\n")

	// Таблица
	b.WriteString(fmt.Sprintf("\033[1;36m│\033[0m \033[1m%-18s %-16s %-10s %-8s %-14s\033[0m  \033[1;36m│\033[0m\n",
		"ИМЯ", "IP", "СТАТУС", "ПИНГ", "ПОСЛЕДНИЙ"))
	b.WriteString(fmt.Sprintf("\033[1;36m│\033[0m \033[2m%s\033[0m  \033[1;36m│\033[0m\n", strings.Repeat("─", 64)))

	peers := make([]*PeerInfo, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].Name < peers[j].Name
	})

	if len(peers) == 0 {
		b.WriteString(fmt.Sprintf("\033[1;36m│\033[0m \033[2m%-64s\033[0m  \033[1;36m│\033[0m\n", "Нет известных пиров"))
	} else {
		for _, peer := range peers {
			color := "\033[33m" // UNKNOWN
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
				ago := time.Since(peer.LastSeen).Truncate(time.Second)
				lastSeen = fmt.Sprintf("%sназад", ago)
			} else if peer.IP == "" {
				lastSeen = "(нет IP)"
			}

			name := peer.Name
			if len(name) > 18 {
				name = name[:15] + "..."
			}

			b.WriteString(fmt.Sprintf("\033[1;36m│\033[0m %-18s %-16s %s%-10s\033[0m %-8s %-14s  \033[1;36m│\033[0m\n",
				name, peer.IP, color, peer.Status, latency, lastSeen))
		}
	}

	b.WriteString("\033[1;36m├──────────────────────────────────────────────────────────────┤\033[0m\n")
	b.WriteString("\033[1;36m│\033[0m \033[2m[Q] Выход  [R] Ping всех  [P] Ping всех\033[0m                 \033[1;36m│\033[0m\n")
	b.WriteString("\033[1;36m└──────────────────────────────────────────────────────────────┘\033[0m\n")

	fmt.Print(b.String())
}

// inputLoop обрабатывает ввод.
func (m *Monitor) inputLoop() {
	buf := make([]byte, 1)
	for {
		select {
		case <-m.stopCh:
			return
		default:
		}
		os.Stdin.Read(buf)
		switch buf[0] {
		case 'q', 'Q', 3:
			m.Stop()
			return
		case 'r', 'R', 'p', 'P':
			m.pingAll()
		}
	}
}

// pingLoop каждые 3 секунды пингует всех пиров.
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

// pingAll пингует всех пиров параллельно.
func (m *Monitor) pingAll() {
	m.mu.RLock()
	peers := make([]*PeerInfo, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	m.mu.RUnlock()

	var wg sync.WaitGroup
	for _, peer := range peers {
		if peer.IP == "" {
			continue // пропускаем пиров без IP (из TrustStore)
		}
		wg.Add(1)
		go func(p *PeerInfo) {
			defer wg.Done()
			m.pingPeer(p)
		}(peer)
	}
	wg.Wait()
}

// pingPeer проверяет доступность пира через TCP connect к TLS-порту.
func (m *Monitor) pingPeer(peer *PeerInfo) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", peer.IP, peer.TLSPort),
		3*time.Second)
	latency := time.Since(start)

	m.mu.Lock()
	defer m.mu.Unlock()

	if err != nil {
		if peer.Status == StatusOnline {
			peer.Status = StatusOffline
		} else if peer.Status != StatusOffline {
			peer.Status = StatusUnknown
		}
		peer.Latency = 0
	} else {
		conn.Close()
		peer.Status = StatusOnline
		peer.Latency = latency
		peer.LastSeen = time.Now()
		peer.ConnCount++
	}
}

// RunMonitor запускает TUI-монитор.
func RunMonitor(cfg *Config) error {
	keyPath, _, _ := cfg.BeaconPaths()
	nodeID := GenerateNodeID()

	edKey, err := loadEd25519Key(keyPath)
	if err == nil {
		pub := edKey.Public().(ed25519.PublicKey)
		nodeID = [16]byte(pub[:16])
	}

	// Загружаем TrustStore для получения списка известных пиров
	var ts *TrustStore
	_, _, caPath := cfg.BeaconPaths()
	crlPath := cfg.DataDir + "/ca/crl.pem"
	if _, statErr := os.Stat(caPath); statErr == nil {
		ts, _ = NewTrustStore(caPath, crlPath)
	}

	monitor := NewMonitor(cfg, nodeID, ts)
	defer monitor.Stop()

	log.SetOutput(os.Stderr)
	log.Printf("[Monitor] запуск монитора для %s", cfg.NodeName)

	return monitor.Run()
}
