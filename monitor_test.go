package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestBeaconStateRoundTrip — state.json переживает запись и чтение.
func TestBeaconStateRoundTrip(t *testing.T) {
	dir := t.TempDir()

	_, caCertPEM, caErr := GenerateCA(dir, DefaultCALifetime)
	if caErr != nil {
		t.Fatalf("GenerateCA: %v", caErr)
	}
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	mine, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-mine", time.Hour, RoleServer)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	peer, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-other", time.Hour, RolePeer)
	if err != nil {
		t.Fatalf("IssueCertificate(peer): %v", err)
	}

	cfg := DefaultConfig()
	cfg.DataDir = dir
	cfg.NodeName = "beacon-mine"

	node, err := NewBeaconNode(cfg)
	if err != nil {
		t.Fatalf("NewBeaconNode: %v", err)
	}

	node.mu.Lock()
	node.peers[peer.NodeID] = &DiscoveredPeer{
		NodeID:   peer.NodeID,
		Addr:     mustUDPAddr("192.168.1.166:19840"),
		LastSeen: time.Now(),
	}
	node.mu.Unlock()

	// Записываем и читаем.
	if err := writeStateFile(cfg, node); err != nil {
		t.Fatalf("writeStateFile: %v", err)
	}

	state, err := readBeaconState(cfg.StateFilePath())
	if err != nil {
		t.Fatalf("readBeaconState: %v", err)
	}

	if state.CN != "beacon-mine" {
		t.Fatalf("неверный CN: %s", state.CN)
	}
	if state.NodeID == "" {
		t.Fatal("NodeID должен быть заполнен")
	}

	// Сосед должен быть привязан к имени сертификата, а не к голому nodeID.
	peerIP, ok := state.PeerIPs["beacon-other"]
	if !ok {
		t.Fatalf("сосед не появился в state.json: %v", state.PeerIPs)
	}
	if peerIP != "192.168.1.166" {
		t.Fatalf("неверный IP соседа: %s", peerIP)
	}

	// Свой CN не должен попадать в список пиров.
	if _, self := state.PeerIPs["beacon-mine"]; self {
		t.Fatal("свой узел не должен быть в списке пиров")
	}

	// Повторная запись не должна ./дублировать записи.
	if err := writeStateFile(cfg, node); err != nil {
		t.Fatalf("вторая writeStateFile: %v", err)
	}

	state2, err := readBeaconState(cfg.StateFilePath())
	if err != nil {
		t.Fatalf("повторное чтение: %v", err)
	}
	if len(state2.PeerIPs) != len(state.PeerIPs) {
		t.Fatalf("число пиров изменилось: было %d, стало %d",
			len(state.PeerIPs), len(state2.PeerIPs))
	}

	// Путь к файлу состояния определяется каталогом данных.
	if want := filepath.Join(dir, stateFileName); cfg.StateFilePath() != want {
		t.Fatalf("путь state.json: %s != %s", cfg.StateFilePath(), want)
	}

	// Временный файл не должен оставаться.
	if _, err := os.Stat(cfg.StateFilePath() + ".tmp"); err == nil {
		t.Fatal("временный файл состояния не удалён")
	}

	_ = mine
}

// TestMonitorLoadPeersSkipsCAAndSelf — монитор не показывает CA и себя.
func TestMonitorLoadPeersSkipsCAAndSelf(t *testing.T) {
	dir := t.TempDir()

	_, caCertPEM, caErr := GenerateCA(dir, DefaultCALifetime)
	if caErr != nil {
		t.Fatalf("GenerateCA: %v", caErr)
	}
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	self, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-self", time.Hour, RoleServer)
	if err != nil {
		t.Fatalf("IssueCertificate(self): %v", err)
	}
	_, err = IssueCertificate(caKey, caCertPEM, dir, "beacon-neighbour", time.Hour, RolePeer)
	if err != nil {
		t.Fatalf("IssueCertificate(neighbour): %v", err)
	}

	cfg := DefaultConfig()
	cfg.DataDir = dir
	cfg.NodeName = "beacon-self"

	// TrustStore грузится из каталога, где лежат сертификаты обоих узлов.
	ts, err := NewTrustStore(dir+"/ca/ca-cert.pem", dir+"/ca/crl.pem")
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}

	peers := loadPeers(cfg, ts)

	// Должен остаться ровно один сосед.
	if len(peers) != 1 {
		t.Fatalf("ожидался 1 пир, получено %d: %+v", len(peers), peers)
	}
	if peers[0].Name != "beacon-neighbour" {
		t.Fatalf("неверное имя пира: %s", peers[0].Name)
	}

	// Без IP статус неизвестен — ровно так монитор и должен себя вести,
	// пока не получит state.json.
	if peers[0].IP != "" {
		t.Fatal("у пира из одних сертификатов не должно быть IP")
	}
	if peers[0].Status != statusUnknown {
		t.Fatal("статус без пинга должен быть unknown")
	}

	_ = self
}

// TestPingResultMsgGuardsStaleEntries — устаревший результат пинга
// не должен применяться, если список пиров пересобрался.
func TestPingResultMsgGuardsStaleEntries(t *testing.T) {
	m := model{
		name: "beacon-self",
		peers: []peerInfo{
			{Name: "beacon-a", IP: "192.168.1.1", Port: 1985},
			{Name: "beacon-b", IP: "192.168.1.2", Port: 1985},
		},
	}

	// Результат для индекса 1, но с другим IP — означает, что пиры
	// пересобрались, и применять его нельзя.
	stale := pingResultMsg{Index: 1, IP: "192.168.1.99", Online: true, Latency: time.Millisecond}
	updated, _ := m.Update(stale)

	byValue, ok := updated.(model)
	if !ok {
		t.Fatal("Update должен возвращать model")
	}
	if byValue.peers[1].Status != statusUnknown {
		t.Fatal("устаревший результат не должен применяться")
	}

	// Актуальный результат применяется.
	fresh := pingResultMsg{Index: 1, IP: "192.168.1.2", Online: true, Latency: 5 * time.Millisecond}
	updated2, _ := m.Update(fresh)

	byValue2, ok := updated2.(model)
	if !ok {
		t.Fatal("Update должен возвращать model")
	}
	if byValue2.peers[1].Status != statusOnline {
		t.Fatal("актуальный результат должен применяться")
	}
	if byValue2.peers[1].Ping != 5*time.Millisecond {
		t.Fatalf("неверная задержка: %v", byValue2.peers[1].Ping)
	}

	// Индекс за пределами списка не должен паниковать.
	outOfRange := pingResultMsg{Index: 99, IP: "192.168.1.5", Online: true}
	if _, cmd := m.Update(outOfRange); cmd != nil {
		t.Log("команда после out-of-range результата игнорируется")
	}
}

// TestStateWriterLoopWritesFile — фоновый писатель должен обновлять файл.
func TestStateWriterLoopWritesFile(t *testing.T) {
	dir := t.TempDir()

	_, caCertPEM, caErr := GenerateCA(dir, DefaultCALifetime)
	if caErr != nil {
		t.Fatalf("GenerateCA: %v", caErr)
	}
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	if _, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-writer", time.Hour, RoleServer); err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	cfg := DefaultConfig()
	cfg.DataDir = dir
	cfg.NodeName = "beacon-writer"

	node, err := NewBeaconNode(cfg)
	if err != nil {
		t.Fatalf("NewBeaconNode: %v", err)
	}

	// Пишем один раз и убеждаемся, что файл читается.
	if err := writeStateFile(cfg, node); err != nil {
		t.Fatalf("writeStateFile: %v", err)
	}

	state, err := readBeaconState(cfg.StateFilePath())
	if err != nil {
		t.Fatalf("readBeaconState: %v", err)
	}
	if state.CN != "beacon-writer" {
		t.Fatalf("неверный CN в файле: %s", state.CN)
	}

	if _, err := os.Stat(cfg.StateFilePath()); err != nil {
		t.Fatalf("state.json должен существовать: %v", err)
	}
}

// TestStateExcludesSelfAfterSelfDial — соединение узла с самим собой (клиент
// `beacon ssh` на той же машине приводит к dial на собственный TLS-порт) не
// добавляет узел в список пиров.
//
// Так случилось вживую: в state.json появлялся сам маячок, и монитор показывал
// его среди соседей.
func TestStateExcludesSelfAfterSelfDial(t *testing.T) {
	dir := t.TempDir()

	caCertPEM := newTestCA(t, dir)
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	self, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-self", time.Hour, RoleServer)
	if err != nil {
		t.Fatalf("IssueCertificate(self): %v", err)
	}

	cfg := DefaultConfig()
	cfg.DataDir = dir
	cfg.NodeName = "beacon-self"

	node, err := NewBeaconNode(cfg)
	if err != nil {
		t.Fatalf("NewBeaconNode: %v", err)
	}

	// Имитируем то, что делает dial на собственный TLS-порт.
	node.mu.Lock()
	node.peers[self.NodeID] = &DiscoveredPeer{
		NodeID:   self.NodeID,
		Addr:     mustUDPAddr("127.0.0.1:19840"),
		LastSeen: time.Now(),
	}
	node.mu.Unlock()

	state := node.JSONState()
	if _, ok := state.PeerIPs["beacon-self"]; ok {
		t.Fatalf("собственный узел не должен попадать в peer_ips: %v", state.PeerIPs)
	}

	// И объявление с собственным NodeID не должно порождать пира.
	node.mu.Lock()
	node.peers = make(map[[16]byte]*DiscoveredPeer)
	node.mu.Unlock()

	node.onPeerDiscovered(self.NodeID, mustUDPAddr("127.0.0.1:19840"), PktAnnounce)

	node.mu.RLock()
	peers := len(node.peers)
	node.mu.RUnlock()

	if peers != 0 {
		t.Fatalf("объявление с собственным NodeID не должно добавлять пира, пиров: %d", peers)
	}
}

// mustUDPAddr парсит адрес или падает в тесте.
func mustUDPAddr(addr string) *net.UDPAddr {
	u, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		panic(err)
	}
	return u
}

// TestStatePeerListerRereadsStateFile — отдельный процесс монитора перечитывает
// state.json на каждом тике.
//
// Файл читался один раз при старте, и монитор, запущенный раньше соседа,
// показывал вечные «???»: адреса появлялись в файле уже после чтения.
func TestStatePeerListerRereadsStateFile(t *testing.T) {
	dir := t.TempDir()

	caCertPEM := newTestCA(t, dir)
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	if _, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-self", time.Hour, RoleServer); err != nil {
		t.Fatalf("IssueCertificate(self): %v", err)
	}
	if _, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-neighbour", time.Hour, RolePeer); err != nil {
		t.Fatalf("IssueCertificate(neighbour): %v", err)
	}

	cfg := DefaultConfig()
	cfg.DataDir = dir
	cfg.NodeName = "beacon-self"

	ts, err := NewTrustStore(dir+"/ca/ca-cert.pem", dir+"/ca/crl.pem")
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}

	list := statePeerLister(cfg, ts)

	// Файла состояния ещё нет — показывается имя без адреса.
	peers := list()
	if len(peers) != 1 || peers[0].Name != "beacon-neighbour" || peers[0].IP != "" {
		t.Fatalf("без state.json ожидался сосед без IP, получено: %+v", peers)
	}

	// Маячок записал состояние — адрес обязан появиться при следующем чтении.
	state := &BeaconState{
		CN:        "beacon-self",
		NodeID:    "AABB",
		PeerIPs:   map[string]string{"beacon-neighbour": "192.168.1.166"},
		UpdatedAt: nowRFC3339(),
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("сериализация состояния: %v", err)
	}
	if err := os.WriteFile(cfg.StateFilePath(), data, 0644); err != nil {
		t.Fatalf("запись state.json: %v", err)
	}

	peers = list()
	if len(peers) != 1 || peers[0].IP != "192.168.1.166" {
		t.Fatalf("после появления state.json адрес должен подхватиться: %+v", peers)
	}
}

// TestMergePeersKeepsStatus — обновление списка не сбрасывает статусы
// оставшихся пиров и добавляет новых.
func TestMergePeersKeepsStatus(t *testing.T) {
	m := model{
		name: "beacon-self",
		peers: []peerInfo{
			{Name: "beacon-a", IP: "192.168.1.1", Port: 1985, Status: statusOnline, Ping: 4 * time.Millisecond},
			{Name: "beacon-b", IP: "192.168.1.2", Port: 1985, Status: statusOffline},
		},
	}

	m.mergePeers([]peerInfo{
		{Name: "beacon-a", IP: "192.168.1.1", Port: 1985},
		{Name: "beacon-c", IP: "192.168.1.3", Port: 1985},
	})

	if len(m.peers) != 2 {
		t.Fatalf("ожидались два пира после обновления: %+v", m.peers)
	}

	byName := map[string]peerInfo{}
	for _, p := range m.peers {
		byName[p.Name] = p
	}

	if byName["beacon-a"].Status != statusOnline || byName["beacon-a"].Ping != 4*time.Millisecond {
		t.Fatalf("статус оставшегося пира сброшен: %+v", byName["beacon-a"])
	}
	if byName["beacon-c"].Status != statusUnknown {
		t.Fatalf("новый пир должен быть без статуса: %+v", byName["beacon-c"])
	}
	if _, ok := byName["beacon-b"]; ok {
		t.Fatal("пир, исчезнувший из источника, не должен оставаться в списке")
	}
}

// TestMergePeersResetsStatusOnIPChange — адрес пира сменился, значит это уже
// другой узел: старый статус применять нельзя.
func TestMergePeersResetsStatusOnIPChange(t *testing.T) {
	m := model{
		peers: []peerInfo{{Name: "beacon-a", IP: "192.168.1.1", Status: statusOnline}},
	}

	m.mergePeers([]peerInfo{{Name: "beacon-a", IP: "192.168.1.99"}})

	if m.peers[0].Status != statusUnknown {
		t.Fatalf("при смене адреса статус должен сброситься: %+v", m.peers[0])
	}
}

// TestLivePeerListerUsesNodePeers — в `-tui` адреса берутся из памяти маячка,
// а не из файла: сосед появляется сразу, без ожидания записи state.json.
func TestLivePeerListerUsesNodePeers(t *testing.T) {
	dir := t.TempDir()

	caCertPEM := newTestCA(t, dir)
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	if _, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-self", time.Hour, RoleServer); err != nil {
		t.Fatalf("IssueCertificate(self): %v", err)
	}
	peer, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-neighbour", time.Hour, RolePeer)
	if err != nil {
		t.Fatalf("IssueCertificate(neighbour): %v", err)
	}

	cfg := DefaultConfig()
	cfg.DataDir = dir
	cfg.NodeName = "beacon-self"

	node, err := NewBeaconNode(cfg)
	if err != nil {
		t.Fatalf("NewBeaconNode: %v", err)
	}

	list := livePeerLister(cfg, node)

	// Имя соседа известно по его сертификату, но адреса ещё нет.
	peers := list()
	if len(peers) != 1 || peers[0].Name != "beacon-neighbour" || peers[0].IP != "" {
		t.Fatalf("без пира ожидалось имя соседа без адреса: %+v", peers)
	}

	node.mu.Lock()
	node.peers[peer.NodeID] = &DiscoveredPeer{
		NodeID:   peer.NodeID,
		Addr:     mustUDPAddr("192.168.1.166:19840"),
		LastSeen: time.Now(),
	}
	node.mu.Unlock()

	peers = list()
	if len(peers) != 1 || peers[0].Name != "beacon-neighbour" || peers[0].IP != "192.168.1.166" {
		t.Fatalf("живой сосед должен появиться с адресом: %+v", peers)
	}
}
