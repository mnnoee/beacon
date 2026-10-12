package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
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
	Name   string
	IP     string
	Port   int
	Status peerStatus
	Ping   time.Duration
}

type tickMsg time.Time

// pingResultMsg — результат пинга одного пира.
//
// Приходит сообщением в Update, а не пишется в модель напрямую: правка
// m.peers из горутины — это гонка, от которой -race и защищает.
type pingResultMsg struct {
	Index   int
	IP      string
	Online  bool
	Latency time.Duration
}

// peersMsg — обновлённый список пиров.
//
// Монитор читает источник пиров на каждом тике, а не один раз при старте:
// соседи появляются и исчезают, пока TUI работает, и список, собранный в
// момент запуска, устаревал мгновенно — новые соседи не появлялись никогда,
// а адреса оставались пустыми (статус «???»).
type peersMsg []peerInfo

// peerLister отдаёт актуальный список пиров: имя, адрес и порт.
type peerLister func() []peerInfo

type model struct {
	peers    []peerInfo
	name     string
	list     peerLister
	width    int
	height   int
	quitting bool
}

func (m model) Init() tea.Cmd {
	return tea.Batch(tickCmd(), tea.EnterAltScreen, m.refreshPeersCmd())
}

func tickCmd() tea.Cmd {
	return tea.Tick(3*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// refreshPeersCmd перечитывает список пиров из источника.
func (m model) refreshPeersCmd() tea.Cmd {
	if m.list == nil {
		return nil
	}

	return func() tea.Msg {
		return peersMsg(m.list())
	}
}

// mergePeers применяет новый список, сохраняя статусы пиров, которые остались.
//
// Список пересобирается целиком: без слияния каждый тик сбрасывал бы пинги в
// «???», и монитор мерцал бы вместо того, чтобы показывать состояние соседей.
func (m *model) mergePeers(incoming []peerInfo) {
	previous := make(map[string]peerInfo, len(m.peers))
	for _, p := range m.peers {
		previous[p.Name] = p
	}

	merged := make([]peerInfo, 0, len(incoming))
	for _, p := range incoming {
		if old, ok := previous[p.Name]; ok && old.IP == p.IP {
			p.Status = old.Status
			p.Ping = old.Ping
		}
		merged = append(merged, p)
	}

	sort.Slice(merged, func(i, j int) bool { return merged[i].Name < merged[j].Name })

	m.peers = merged
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
			return m, m.pingAllCmd()
		}

	case tickMsg:
		// Пинги уходят командой, а не выполняются в Update: wg.Wait() прямо
		// здесь блокировал цикл событий на таймаут пинга, и UI замирал.
		return m, tea.Batch(m.pingAllCmd(), tickCmd(), m.refreshPeersCmd())

	case peersMsg:
		m.mergePeers(msg)
		return m, nil

	case pingResultMsg:
		if msg.Index >= 0 && msg.Index < len(m.peers) {
			p := &m.peers[msg.Index]
			if p.IP != msg.IP {
				// Список пиров пересобрался — результат устарел.
				return m, nil
			}
			if msg.Online {
				p.Status = statusOnline
				p.Ping = msg.Latency
			} else {
				p.Status = statusOffline
				p.Ping = 0
			}
		}
		return m, nil
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

	b.WriteString(styleTitle.Render("  Network Beacons Monitor"))
	b.WriteString("\n")

	info := fmt.Sprintf("  Узел: %s  |  Пиров: %d (онлайн: %d)", m.name, len(m.peers), online)
	b.WriteString(info)
	b.WriteString("\n\n")

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

// pingAllCmd пингует всех пиров параллельно и возвращает результаты
// одним пакетом: Update вызывается один раз на пачку, а не на каждый пинг.
func (m model) pingAllCmd() tea.Cmd {
	type pingJob struct {
		index int
		ip    string
		port  int
	}

	// Снимок на момент вызова: Update работает с копией модели, и без копии
	// команда держала бы ссылку на устаревший слайс пиров.
	jobs := make([]pingJob, 0, len(m.peers))
	for i, p := range m.peers {
		if p.IP == "" {
			continue
		}
		jobs = append(jobs, pingJob{index: i, ip: p.IP, port: p.Port})
	}

	return func() tea.Msg {
		var wg sync.WaitGroup
		results := make(chan pingResultMsg, len(jobs))

		for _, job := range jobs {
			wg.Add(1)
			go func(j pingJob) {
				defer wg.Done()

				start := time.Now()
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", j.ip, j.port), 3*time.Second)
				latency := time.Since(start)

				if err != nil {
					results <- pingResultMsg{Index: j.index, IP: j.ip, Online: false}
					return
				}
				conn.Close()
				results <- pingResultMsg{Index: j.index, IP: j.ip, Online: true, Latency: latency}
			}(job)
		}

		wg.Wait()
		close(results)

		// tea.Batch принимает команды, а не сообщения, поэтому каждый
		// результат оборачиваем в команду, которая его возвращает.
		cmds := make([]tea.Cmd, 0, len(jobs))
		for r := range results {
			cmds = append(cmds, func(msg pingResultMsg) tea.Cmd {
				return func() tea.Msg { return msg }
			}(r))
		}

		if len(cmds) == 0 {
			return nil
		}

		return tea.Batch(cmds...)()
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// loadPeers формирует список пиров монитора.
//
// Из TrustStore берутся только имена: адреса знает живой маячок, получивший
// announce. Без IP пиры невозможно пинговать, и все статусы остались бы ??? —
// именно так монитор и выглядел после удаления peers.txt.
func loadPeers(cfg *Config, ts *TrustStore) []peerInfo {
	return peerInfos(cfg, ts, nil)
}

// peerInfos собирает список пиров из сертификатов (имена) и карты адресов.
//
// Имена берутся из сертификатов: CN подписан CA, поэтому он достоверен.
// Адреса приходят извне — от живого маячка или из state.json.
func peerInfos(cfg *Config, ts *TrustStore, ips map[string]string) []peerInfo {
	seen := make(map[string]bool)
	var peers []peerInfo

	appendPeer := func(name, ip string) {
		if name == "" || name == cfg.NodeName || seen[name] {
			return
		}
		seen[name] = true

		p := peerInfo{Name: name, IP: ip, Port: cfg.TLSPort}
		if ip == "" {
			p.Status = statusUnknown
		}
		peers = append(peers, p)
	}

	if ts != nil {
		for _, cert := range ts.getTrustedCerts() {
			if cert == nil || cert.IsCA {
				continue
			}
			appendPeer(cert.Subject.CommonName, ips[cert.Subject.CommonName])
		}
	}

	// Адрес может быть известен раньше, чем сертификат соседа долетел
	// (cert-share идёт по mTLS, а announce — по UDP). Такие пиры тоже нужны.
	for name, ip := range ips {
		appendPeer(name, ip)
	}

	return peers
}

// statePeerLister — источник пиров для отдельного процесса `beacon monitor`.
//
// Файл state.json перечитывается на каждом вызове: маячок пишет его постоянно,
// а одноразовое чтение оставляло монитор с пустыми адресами навсегда.
func statePeerLister(cfg *Config, ts *TrustStore) peerLister {
	warned := false

	return func() []peerInfo {
		ips := make(map[string]string)

		state, err := readBeaconState(cfg.StateFilePath())
		if err != nil {
			if !warned {
				warned = true
				log.Printf("[Monitor] state.json не прочитан (%v): адреса пиров неизвестны, "+
					"показаны только имена из сертификатов", err)
			}
		} else {
			warned = false
			for name, ip := range state.PeerIPs {
				ips[name] = ip
			}
		}

		return peerInfos(cfg, ts, ips)
	}
}

// livePeerLister — источник пиров для `beacon beacon -tui`.
//
// Здесь адреса берутся прямо из памяти маячка, а не из файла: тот же процесс
// и так знает всех пиров, а файл обновляется с задержкой в секунду.
func livePeerLister(cfg *Config, node *BeaconNode) peerLister {
	return func() []peerInfo {
		ips := make(map[string]string)

		node.mu.RLock()
		for _, peer := range node.peers {
			if peer.Addr == nil {
				continue
			}

			cert, err := node.trustStore.FindCertByNodeID(peer.NodeID)
			if err != nil || cert == nil {
				// Сертификат соседа ещё не пришёл по cert-share: имя неизвестно,
				// показывать нечего.
				continue
			}

			ips[cert.Subject.CommonName] = peer.Addr.IP.String()
		}
		node.mu.RUnlock()

		return peerInfos(cfg, node.trustStore, ips)
	}
}

// writeStateFile записывает состояние маячка для отдельного процесса
// монитора. JSON, а не дамп структур: читатель не должен зависеть от
// внутренних полей BeaconNode.
func writeStateFile(cfg *Config, node *BeaconNode) error {
	state := node.JSONState()

	path := cfg.StateFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("создание каталога состояния: %w", err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("сериализация состояния: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("запись состояния: %w", err)
	}

	return os.Rename(tmp, path)
}

// RunMonitor запускает монитор отдельным процессом.
//
// Пиры берутся из state.json, который пишет маячок: у монитора нет доступа к
// памяти узла, и без этого файла он видел бы только имена из сертификатов.
func RunMonitor(cfg *Config) error {
	var ts *TrustStore
	_, _, caPath := cfg.BeaconPaths()
	crlPath := cfg.DataDir + "/ca/crl.pem"
	if _, e := os.Stat(caPath); e == nil {
		ts, _ = NewTrustStore(caPath, crlPath)
	}

	return runMonitor(cfg, statePeerLister(cfg, ts))
}

// runMonitor запускает TUI с указанным источником пиров.
func runMonitor(cfg *Config, list peerLister) error {
	m := model{
		peers: list(),
		name:  cfg.NodeName,
		list:  list,
	}

	// Логи не должны утекать в alt-screen.
	log.SetOutput(os.Stderr)

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()

	return err
}
