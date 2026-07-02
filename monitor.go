package main

import (
	"crypto/ed25519"
	"crypto/tls"
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

// PeerStatus — статус пира в сети.
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

// PeerInfo — информация о пире для отображения в TUI.
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

// Monitor — TUI-монитор для отображения состояния маячка.
type Monitor struct {
	mu    sync.RWMutex
	peers map[[16]byte]*PeerInfo

	cfg     *Config
	stopCh  chan struct{}
	refresh chan struct{}

	// Системная информация
	nodeName string
	nodeID   [16]byte
	uptime   time.Time
}

// NewMonitor создаёт новый TUI-монитор.
func NewMonitor(cfg *Config, nodeID [16]byte) *Monitor {
	return &Monitor{
		peers:    make(map[[16]byte]*PeerInfo),
		cfg:      cfg,
		stopCh:   make(chan struct{}),
		refresh:  make(chan struct{}, 1),
		nodeName: cfg.NodeName,
		nodeID:   nodeID,
		uptime:   time.Now(),
	}
}

// AddPeer добавляет или обновляет информацию о пире.
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

// RemovePeer помечает пира как offline.
func (m *Monitor) RemovePeer(id [16]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if peer, ok := m.peers[id]; ok {
		peer.Status = StatusOffline
	}

	select {
	case m.refresh <- struct{}{}:
	default:
	}
}

// Run запускает TUI-монитор.
func (m *Monitor) Run() error {
	// Переключаем терминал в raw mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("переключение в raw mode: %w", err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	// Очищаем экран
	fmt.Print("\033[2J\033[H")
	fmt.Print("\033[?25l") // скрываем курсор
	defer fmt.Print("\033[?25h") // показываем курсор

	// Запускаем фоновые процессы
	go m.pingLoop()
	go m.inputLoop()

	// Основной цикл отрисовки
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

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

// Stop останавливает монитор.
func (m *Monitor) Stop() {
	close(m.stopCh)
}

// render отрисовывает TUI.
func (m *Monitor) render() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Очищаем экран
	fmt.Print("\033[2J\033[H")

	// Заголовок
	m.printHeader()

	// Таблица пиров
	m.printPeerTable()

	// Нижняя панель
	m.printFooter()
}

// printHeader отрисовывает заголовок TUI.
func (m *Monitor) printHeader() {
	uptime := time.Since(m.uptime).Truncate(time.Second)
	peerCount := len(m.peers)
	onlineCount := 0
	for _, p := range m.peers {
		if p.Status == StatusOnline {
			onlineCount++
		}
	}

	fmt.Printf("\033[1;36m╔══════════════════════════════════════════════════════════════╗\033[0m\n")
	fmt.Printf("\033[1;36m║\033[0m \033[1;37mNetwork Beacons Monitor\033[0m                                    \033[1;36m║\033[0m\n")
	fmt.Printf("\033[1;36m╠══════════════════════════════════════════════════════════════╣\033[0m\n")
	fmt.Printf("\033[1;36m║\033[0m Узел: \033[1;33m%-20s\033[0m ID: %X  \033[1;36m║\033[0m\n", m.nodeName, m.nodeID[:8])
	fmt.Printf("\033[1;36m║\033[0m Аптайм: \033[1;32m%-12s\033[0m Пиров: \033[1;33m%d\033[0m (онлайн: \033[1;32m%d\033[0m)   \033[1;36m║\033[0m\n",
		uptime, peerCount, onlineCount)
	fmt.Printf("\033[1;36m╠══════════════════════════════════════════════════════════════╣\033[0m\n")
}

// printPeerTable отрисовывает таблицу пиров.
func (m *Monitor) printPeerTable() {
	// Заголовок таблицы
	fmt.Printf("\033[1;36m║\033[0m \033[1m%-20s %-18s %-8s %-10s %-16s\033[0m  \033[1;36m║\033[0m\n",
		"ИМЯ", "IP", "СТАТУС", "ЛАТЕНСИ", "ПОСЛЕДНИЙ")

	fmt.Printf("\033[1;36m║\033[0m \033[2m%s\033[0m  \033[1;36m║\033[0m\n",
		strings.Repeat("─", 70))

	// Сортируем пиры по имени
	peers := make([]*PeerInfo, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].Name < peers[j].Name
	})

	if len(peers) == 0 {
		fmt.Printf("\033[1;36m║\033[0m \033[2m%-70s\033[0m  \033[1;36m║\033[0m\n", "Ожидание обнаружения пиров...")
		return
	}

	for _, peer := range peers {
		// Цвет статуса
		statusColor := "\033[33m" // жёлтый (UNKNOWN)
		if peer.Status == StatusOnline {
			statusColor = "\033[32m" // зелёный
		} else if peer.Status == StatusOffline {
			statusColor = "\033[31m" // красный
		}

		// Латенсия
		latency := "—"
		if peer.Latency > 0 {
			latency = fmt.Sprintf("%dms", peer.Latency.Milliseconds())
		}

		// Время с последнего обнаружения
		lastSeen := "—"
		if !peer.LastSeen.IsZero() {
			ago := time.Since(peer.LastSeen).Truncate(time.Second)
			lastSeen = fmt.Sprintf("%s назад", ago)
		}

		name := peer.Name
		if len(name) > 20 {
			name = name[:17] + "..."
		}

		fmt.Printf("\033[1;36m║\033[0m %-20s %-18s %s%-8s\033[0m %-10s %-16s  \033[1;36m║\033[0m\n",
			name, peer.IP, statusColor, peer.Status, latency, lastSeen)
	}
}

// printFooter отрисовывает нижнюю панель.
func (m *Monitor) printFooter() {
	fmt.Printf("\033[1;36m╠══════════════════════════════════════════════════════════════╣\033[0m\n")
	fmt.Printf("\033[1;36m║\033[0m \033[2m[Q] Выход  [R] Обновить  [P] Ping всех пиров\033[0m              \033[1;36m║\033[0m\n")
	fmt.Printf("\033[1;36m╚══════════════════════════════════════════════════════════════╝\033[0m\n")
}

// inputLoop обрабатывает ввод пользователя.
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
		case 'q', 'Q', 3: // q, Q, Ctrl+C
			m.Stop()
			return
		case 'r', 'R':
			m.pingAll()
			m.render()
		case 'p', 'P':
			m.pingAll()
			m.render()
		}
	}
}

// pingLoop периодически пингует всех пиров.
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

// pingAll пингует всех известных пиров.
func (m *Monitor) pingAll() {
	m.mu.RLock()
	peers := make([]*PeerInfo, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	m.mu.RUnlock()

	var wg sync.WaitGroup
	for _, peer := range peers {
		wg.Add(1)
		go func(p *PeerInfo) {
			defer wg.Done()
			m.pingPeer(p)
		}(peer)
	}
	wg.Wait()
}

// pingPeer пингует один пир через TCP-подключение к TLS-порту.
func (m *Monitor) pingPeer(peer *PeerInfo) {
	start := time.Now()

	// TCP- connect к TLS-порту (быстрый способ проверить доступность)
	conn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", peer.IP, peer.TLSPort),
		3*time.Second)

	latency := time.Since(start)

	m.mu.Lock()
	defer m.mu.Unlock()

	if err != nil {
		// Если не удалось подключиться — проверяем, был ли пир онлайн
		if peer.Status == StatusOnline {
			peer.Status = StatusOffline
		} else {
			peer.Status = StatusUnknown
		}
		peer.Latency = 0
	} else {
		conn.Close()
		peer.Status = StatusOnline
		peer.Latency = latency
		peer.ConnCount++
	}
}

// TLSConfigForPing создаёт минимальный TLS-конфиг для ping-проверки.
func tlsDialForPing(addr string, timeout time.Duration) (*tls.Conn, error) {
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	return tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp", addr, config,
	)
}

// RunMonitor запускает TUI-монитор для указанного маячка.
func RunMonitor(cfg *Config) error {
	// Загружаем Ed25519 ключ для определения nodeID
	keyPath, _, _ := cfg.BeaconPaths()
	nodeID := GenerateNodeID()

	edKey, err := loadEd25519Key(keyPath)
	if err == nil {
		pub := edKey.Public().(ed25519.PublicKey)
		nodeID = [16]byte(pub[:16])
	}

	monitor := NewMonitor(cfg, nodeID)
	defer monitor.Stop()

	log.SetOutput(os.Stderr) // логи в stderr, TUI в stdout
	log.Printf("[Monitor] запуск монитора для %s", cfg.NodeName)

	return monitor.Run()
}
