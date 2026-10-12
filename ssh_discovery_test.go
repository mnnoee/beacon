package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// freeUDPPort возвращает свободный UDP-порт на loopback.
func freeUDPPort(t *testing.T) int {
	t.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("резервирование UDP-порта: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	conn.Close()

	return port
}

// newTestCA создаёт CA в отдельной директории и возвращает PEM сертификата.
func newTestCA(t *testing.T, dir string) []byte {
	t.Helper()

	_, caCertPEM, err := GenerateCA(dir, DefaultCALifetime)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	return caCertPEM
}

// discoveryFixture — раскладка для тестов discovery-клиента `beacon ssh`.
type discoveryFixture struct {
	caKey     []byte
	caCertPEM []byte

	remoteDir  string
	remoteCert *IssuedNode

	clientDir string
	clientTS  *TrustStore
	cfg       *Config
}

// newDiscoveryFixture готовит два узла под одним CA: сосед, к которому
// подключаемся, и клиент с сертификатом соседа в peers/ (как после cert-share).
func newDiscoveryFixture(t *testing.T) *discoveryFixture {
	t.Helper()

	caDir := t.TempDir()
	caCertPEM := newTestCA(t, caDir)
	caKeyPath := filepath.Join(caDir, "ca", "ca-key.pem")
	caKey, err := LoadCAKey(caKeyPath)
	if err != nil {
		t.Fatalf("LoadCAKey: %v", err)
	}
	caKeyPEM := mustReadFile(t, caKeyPath)

	remote, err := IssueCertificate(caKey, caCertPEM, caDir, "beacon-remote", time.Hour, RoleServer)
	if err != nil {
		t.Fatalf("IssueCertificate (сосед): %v", err)
	}

	clientDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(clientDir, "ca"), 0700); err != nil {
		t.Fatalf("MkdirAll ca: %v", err)
	}
	if err := os.WriteFile(filepath.Join(clientDir, "ca", "ca-cert.pem"), caCertPEM, 0644); err != nil {
		t.Fatalf("запись CA-сертификата: %v", err)
	}

	if _, err := IssueCertificate(caKey, caCertPEM, clientDir, "beacon-cli", time.Hour, RolePeer); err != nil {
		t.Fatalf("IssueCertificate (клиент): %v", err)
	}

	// Сертификат соседа получен по cert-share и лежит в peers/.
	if err := os.MkdirAll(PeersDir(clientDir), 0700); err != nil {
		t.Fatalf("MkdirAll peers: %v", err)
	}
	if err := os.WriteFile(PeerCertPath(clientDir, "beacon-remote"), mustReadFile(t, remote.CertPath), 0644); err != nil {
		t.Fatalf("запись сертификата соседа: %v", err)
	}

	clientTS, err := NewTrustStore(filepath.Join(clientDir, "ca", "ca-cert.pem"),
		filepath.Join(clientDir, "ca", "crl.pem"))
	if err != nil {
		t.Fatalf("NewTrustStore (клиент): %v", err)
	}

	cfg := DefaultConfig()
	cfg.DataDir = clientDir
	cfg.NodeName = "beacon-cli"
	cfg.DiscoveryPort = freeUDPPort(t)
	cfg.BroadcastAddr = "127.255.255.255"

	return &discoveryFixture{
		caKey:      caKeyPEM,
		caCertPEM:  caCertPEM,
		remoteDir:  caDir,
		remoteCert: remote,
		clientDir:  clientDir,
		clientTS:   clientTS,
		cfg:        cfg,
	}
}

// client возвращает SSH-клиента с загруженным TrustStore.
func (f *discoveryFixture) client(t *testing.T) *SSHClient {
	t.Helper()

	c := NewSSHClient(f.cfg)
	c.SetTrustStore(f.clientTS)

	return c
}

// startNeighbour поднимает настоящий маячок-сосед на loopback.
func (f *discoveryFixture) startNeighbour(t *testing.T) *Discovery {
	t.Helper()

	remoteTS, err := NewTrustStore(filepath.Join(f.remoteDir, "ca", "ca-cert.pem"),
		filepath.Join(f.remoteDir, "ca", "crl.pem"))
	if err != nil {
		t.Fatalf("NewTrustStore (сосед): %v", err)
	}

	remoteED, err := loadEd25519Key(filepath.Join(f.remoteDir, "beacon-remote", ed25519KeyFile))
	if err != nil {
		t.Fatalf("Ed25519-ключ соседа: %v", err)
	}

	disc := NewDiscovery(f.remoteCert.NodeID, remoteED, f.cfg.DiscoveryPort,
		f.cfg.BroadcastAddr, "0.0.0.0", NewRateLimiter(1000, 100))
	disc.SetTrustStore(remoteTS)
	if err := disc.Start(); err != nil {
		t.Fatalf("запуск discovery соседа: %v", err)
	}
	t.Cleanup(disc.Stop)

	return disc
}

// signEcho собирает корректно подписанный PktEcho от указанного отправителя.
func signEcho(t *testing.T, nodeID [16]byte, priv ed25519.PrivateKey) []byte {
	t.Helper()

	payload, err := (&AnnouncePayload{Ed25519Pub: priv.Public().(ed25519.PublicKey)}).Serialize()
	if err != nil {
		t.Fatalf("payload: %v", err)
	}

	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktEcho,
		NodeID:    nodeID,
		Timestamp: time.Now().Unix(),
		Payload:   payload,
	}
	if _, err := rand.Read(pkt.Nonce[:]); err != nil {
		t.Fatalf("nonce: %v", err)
	}

	return SignPacket(pkt, priv)
}

// TestDiscoverBeaconResolvesNameToAddress — клиент `beacon ssh <имя>` находит
// адрес соседа по его CN через broadcast-объявление.
//
// Раньше объявление уходило с отдельного сокета DialUDP: сосед отвечал по адресу
// отправителя — на эфемерный порт, который к тому моменту уже закрывался. Маячок
// видел announce, отвечал, а клиент упирался в «не ответил в сети».
func TestDiscoverBeaconResolvesNameToAddress(t *testing.T) {
	f := newDiscoveryFixture(t)
	f.startNeighbour(t)

	ip, err := f.client(t).discoverBeacon("beacon-remote")
	if err != nil {
		t.Fatalf("discoverBeacon: %v", err)
	}
	if ip != "127.0.0.1" {
		t.Fatalf("ожидался адрес 127.0.0.1, получено %s", ip)
	}
}

// TestDiscoverBeaconRejectsSpoofedResponse — ответ с чужим NodeID и чужим ключом
// не переводит подключение на чужой адрес.
func TestDiscoverBeaconRejectsSpoofedResponse(t *testing.T) {
	f := newDiscoveryFixture(t)

	// Настоящего соседа в сети нет — отвечает только подмена.
	_, roguePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("генерация ключа подмены: %v", err)
	}

	packet := signEcho(t, f.remoteCert.NodeID, roguePriv)

	spoof, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
		&net.UDPAddr{IP: net.ParseIP("127.0.0.255"), Port: f.cfg.DiscoveryPort})
	if err != nil {
		t.Fatalf("сокет подмены: %v", err)
	}
	defer spoof.Close()

	go func() {
		for i := 0; i < 10; i++ {
			spoof.Write(packet)
			time.Sleep(discoveryAnnounceInterval)
		}
	}()

	if _, err := f.client(t).discoverBeacon("beacon-remote"); err == nil {
		t.Fatal("ответ, подписанный чужим ключом, не должен приводить к подключению")
	}
}

// TestPickResponderIP — выбор адреса среди ответивших: один ответ принимается,
// отсутствие и множественные ответы — отказ. Два адреса на один NodeID означают
// клона или подмену, и произвольно выбирать из них нельзя.
func TestPickResponderIP(t *testing.T) {
	ip, err := pickResponderIP("beacon-remote", map[string]int{"192.168.1.4": 2})
	if err != nil {
		t.Fatalf("единственный ответ должен приниматься: %v", err)
	}
	if ip != "192.168.1.4" {
		t.Fatalf("неверный адрес: %s", ip)
	}

	if _, err := pickResponderIP("beacon-remote", nil); err == nil {
		t.Fatal("без ответов подключение невозможно")
	}

	_, err = pickResponderIP("beacon-remote", map[string]int{"192.168.1.4": 1, "192.168.1.166": 1})
	if err == nil {
		t.Fatal("при двух отвечающих адресах подключение должно быть отменено")
	}
	if !strings.Contains(err.Error(), "несколько адресов") {
		t.Fatalf("ожидалось сообщение про несколько адресов, получено: %v", err)
	}
}

// TestDiscoverBeaconUnknownName — неизвестное имя отвергается с понятным текстом.
func TestDiscoverBeaconUnknownName(t *testing.T) {
	f := newDiscoveryFixture(t)

	if _, err := f.client(t).discoverBeacon("beacon-нет-такого"); err == nil {
		t.Fatal("неизвестное имя должно отвергаться")
	}
}

// TestDiscoverBeaconRevokedTarget — отозванный узел не подключается, даже если
// его сертификат ещё лежит в peers/.
func TestDiscoverBeaconRevokedTarget(t *testing.T) {
	f := newDiscoveryFixture(t)

	// Отзыв выполняет CA-машина: подписать CRL может только она. Клиент получает
	// готовый CRL — ровно так же, как по gossip.
	caTS, err := NewTrustStore(filepath.Join(f.remoteDir, "ca", "ca-cert.pem"),
		filepath.Join(f.remoteDir, "ca", "crl.pem"))
	if err != nil {
		t.Fatalf("NewTrustStore (CA): %v", err)
	}
	if err := caTS.Revoke(f.remoteCert.Serial, 1); err != nil {
		t.Fatalf("отзыв сертификата соседа: %v", err)
	}
	if err := caTS.SaveCRL(); err != nil {
		t.Fatalf("сохранение CRL: %v", err)
	}

	if err := os.WriteFile(filepath.Join(f.clientDir, "ca", "crl.pem"),
		mustReadFile(t, filepath.Join(f.remoteDir, "ca", "crl.pem")), 0644); err != nil {
		t.Fatalf("передача CRL клиенту: %v", err)
	}

	clientTS, err := NewTrustStore(filepath.Join(f.clientDir, "ca", "ca-cert.pem"),
		filepath.Join(f.clientDir, "ca", "crl.pem"))
	if err != nil {
		t.Fatalf("NewTrustStore (клиент с CRL): %v", err)
	}

	cfg := DefaultConfig()
	cfg.DataDir = f.clientDir
	cfg.NodeName = "beacon-cli"
	cfg.DiscoveryPort = f.cfg.DiscoveryPort
	cfg.BroadcastAddr = f.cfg.BroadcastAddr

	c := NewSSHClient(cfg)
	c.SetTrustStore(clientTS)

	_, err = c.discoverBeacon("beacon-remote")
	if err == nil {
		t.Fatal("отозванный узел не должен приниматься")
	}
	if !strings.Contains(err.Error(), "отозван") {
		t.Fatalf("ожидалось сообщение об отзыве, получено: %v", err)
	}
}

// TestVerifyDiscoveryEcho — проверка ответов discovery по ключу из сертификата.
func TestVerifyDiscoveryEcho(t *testing.T) {
	f := newDiscoveryFixture(t)

	priv, err := loadEd25519Key(filepath.Join(f.remoteDir, "beacon-remote", ed25519KeyFile))
	if err != nil {
		t.Fatalf("Ed25519-ключ соседа: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	nodeID := NodeIDFromEd25519Pub(pub)

	if err := verifyDiscoveryEcho(signEcho(t, nodeID, priv), nodeID, pub); err != nil {
		t.Fatalf("корректный ответ должен приниматься: %v", err)
	}

	roguePub, roguePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("генерация ключа подмены: %v", err)
	}

	cases := []struct {
		name   string
		packet []byte
	}{
		{"чужой ключ при чужом NodeID", signEcho(t, NodeIDFromEd25519Pub(roguePub), roguePriv)},
		{"чужой ключ с целевым NodeID", signEcho(t, nodeID, roguePriv)},
		{"испорченная подпись", flipSignature(signEcho(t, nodeID, priv))},
		{"обрыв пакета", signEcho(t, nodeID, priv)[:MinPacketSize-1]},
		{"не discovery-пакет", []byte("просто мусор")},
	}

	for _, tc := range cases {
		if err := verifyDiscoveryEcho(tc.packet, nodeID, pub); err == nil {
			t.Fatalf("%s: ответ должен отвергаться", tc.name)
		}
	}
}

// flipSignature портит последний байт подписи.
func flipSignature(packet []byte) []byte {
	out := append([]byte(nil), packet...)
	out[len(out)-1] ^= 0xFF

	return out
}
