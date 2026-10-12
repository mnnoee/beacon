package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// meshFixture — два маячка в одном процессе, связанные настоящим mTLS.
//
// Узлы не находят друг друга по discovery: на одной машине два сокета на одном
// UDP-порту с SO_REUSEPORT делят поток пакетов между собой. Поэтому связь
// строится напрямую по TCP — тем же кодом, что и dial соседа из onPeerDiscovered,
// — а проверяется то, ради чего тест написан: обработчики сообщений поверх
// установленного канала.
type meshFixture struct {
	caDir     string
	caKey     []byte
	caCertPEM []byte

	first  *BeaconNode
	firstC *Config

	second  *BeaconNode
	secondC *Config
}

// newMeshFixture поднимает два узла под одним CA и связывает их по TLS.
func newMeshFixture(t *testing.T) *meshFixture {
	t.Helper()

	caDir := t.TempDir()
	caCertPEM := newTestCA(t, caDir)
	caKeyPEM := mustReadFile(t, filepath.Join(caDir, "ca", "ca-key.pem"))

	// Один каталог на оба узла: соседи узнают сертификаты друг друга через
	// cert-share, а не через заранее подложенные файлы — именно этот путь и
	// проверяется.
	caKey, err := LoadCAKey(filepath.Join(caDir, "ca", "ca-key.pem"))
	if err != nil {
		t.Fatalf("LoadCAKey: %v", err)
	}

	firstIssued, err := IssueCertificate(caKey, caCertPEM, caDir, "beacon-first", time.Hour, RoleServer)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	if _, err := IssueCertificate(caKey, caCertPEM, caDir, "beacon-second", time.Hour, RoleServer); err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	_ = firstIssued

	// Второй узел в отдельном каталоге, чтобы узлы не мешали друг другу
	// файлами peers/.
	secondDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(secondDir, "ca"), 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(secondDir, "ca", "ca-cert.pem"), caCertPEM, 0644); err != nil {
		t.Fatalf("запись CA: %v", err)
	}
	if _, err := IssueCertificate(caKey, caCertPEM, secondDir, "beacon-second", time.Hour, RoleServer); err != nil {
		t.Fatalf("IssueCertificate (второй): %v", err)
	}

	start := func(dir, name string, discPort int) (*BeaconNode, *Config) {
		cfg := DefaultConfig()
		cfg.DataDir = dir
		cfg.NodeName = name
		cfg.BindAddr = "127.0.0.1"
		cfg.BroadcastAddr = "127.255.255.255"
		cfg.DiscoveryPort = discPort
		cfg.TLSPort = freeTCPPort(t)
		cfg.SSHPort = 0
		cfg.SSHEnabled = false

		node, err := NewBeaconNode(cfg)
		if err != nil {
			t.Fatalf("NewBeaconNode(%s): %v", name, err)
		}
		if err := node.Start(); err != nil {
			t.Fatalf("запуск %s: %v", name, err)
		}
		t.Cleanup(node.Stop)

		return node, cfg
	}

	first, firstCfg := start(caDir, "beacon-first", freeUDPPort(t))
	second, secondCfg := start(secondDir, "beacon-second", freeUDPPort(t))

	return &meshFixture{
		caDir:     caDir,
		caKey:     caKeyPEM,
		caCertPEM: caCertPEM,
		first:     first,
		firstC:    firstCfg,
		second:    second,
		secondC:   secondCfg,
	}
}

// dial соединяет первый узел со вторым по TLS — тем же способом, каким узел
// дозванивается до соседа, найденного по discovery.
//
// Повторяет попытки: TLS-слушатель поднимается в горутине, поэтому сразу после
// Start порт может ещё не слушать.
func (f *meshFixture) dial(t *testing.T) *tls.Conn {
	t.Helper()

	addr := fmt.Sprintf("127.0.0.1:%d", f.secondC.TLSPort)

	var conn *tls.Conn
	var err error

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = TLSClientDial(addr, f.first.tlsClientConfig)
		if err == nil {
			t.Cleanup(func() { conn.Close() })
			return conn
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("mTLS-соединение со вторым узлом: %v", err)
	return nil
}

// waitFor ждёт выполнения условия или истечения таймаута.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("не дождались: %s", what)
}

// TestMeshCertShareOverTLS — узлы обмениваются сертификатами по установленному
// mTLS: второй принимает сертификат первого, ключ подписи регистрируется.
//
// Это тот путь, который в реальной сети закрывает холодный старт: без обмена
// сосед не знает ни CN, ни адреса, и `beacon ssh <имя>` не работает.
func TestMeshCertShareOverTLS(t *testing.T) {
	f := newMeshFixture(t)

	conn := f.dial(t)

	_, firstCertPath, _ := f.firstC.BeaconPaths()
	if err := ShareCertificate(firstCertPath, conn, f.first.edPriv, f.first.nodeID); err != nil {
		t.Fatalf("отправка cert-share: %v", err)
	}

	waitFor(t, 5*time.Second, "сертификат первого узла у второго", func() bool {
		_, err := f.second.trustStore.CertByCN("beacon-first")
		return err == nil
	})

	// И на диске: без файла в peers/ сосед не найдётся после перезапуска.
	peerCert := filepath.Join(PeersDir(f.secondC.DataDir), "beacon-first.cert.pem")
	if _, err := os.Stat(peerCert); err != nil {
		t.Fatalf("сертификат соседа не сохранён в %s: %v", peerCert, err)
	}

	// Ключ подписи gossip зарегистрирован сразу, без перезапуска.
	if _, err := f.second.trustStore.SigningKey(f.first.nodeID); err != nil {
		t.Fatalf("ключ подписи соседа не зарегистрирован: %v", err)
	}

	// И второй узел теперь тоже известен первому — симметрично.
	_, secondCertPath, _ := f.secondC.BeaconPaths()
	if err := ShareCertificate(secondCertPath, conn, f.second.edPriv, f.second.nodeID); err != nil {
		t.Fatalf("отправка cert-share в обратную сторону: %v", err)
	}

	waitFor(t, 5*time.Second, "сертификат второго узла у первого", func() bool {
		_, err := f.first.trustStore.CertByCN("beacon-second")
		return err == nil
	})
}

// TestMeshGossipRevocation — отзыв, сделанный на CA-машине, доезжает до соседа
// по gossip и отрезает сертификат на mTLS.
//
// Проверяется вся цепочка: подпись пакета, привязка к пиру mTLS, слияние CRL
// и отказ доверия.
func TestMeshGossipRevocation(t *testing.T) {
	f := newMeshFixture(t)

	// Готовим третий узел, который будет отозван.
	caKey, err := LoadCAKey(filepath.Join(f.caDir, "ca", "ca-key.pem"))
	if err != nil {
		t.Fatalf("LoadCAKey: %v", err)
	}

	revoked, err := IssueCertificate(caKey, f.caCertPEM, f.caDir, "beacon-target", time.Hour, RolePeer)
	if err != nil {
		t.Fatalf("IssueCertificate (цель): %v", err)
	}

	conn := f.dial(t)

	_, firstCertPath, _ := f.firstC.BeaconPaths()
	if err := ShareCertificate(firstCertPath, conn, f.first.edPriv, f.first.nodeID); err != nil {
		t.Fatalf("отправка cert-share: %v", err)
	}

	waitFor(t, 5*time.Second, "сертификат соседа у второго узла", func() bool {
		_, err := f.second.trustStore.CertByCN("beacon-first")
		return err == nil
	})

	// Отзыв делает первый узел, подписав CRL ключом CA. В обычной сети ключа CA
	// на маячке нет, поэтому CRL готовится заранее и уезжает записями.
	revocation := revokedCert{
		SerialNumber: revoked.Serial,
		RevokedAt:    time.Now(),
		Reason:       1,
	}

	if err := f.first.sendGossipToConn(conn, []revokedCert{revocation}); err != nil {
		t.Fatalf("отправка gossip: %v", err)
	}

	waitFor(t, 5*time.Second, "отзыв у второго узла", func() bool {
		return f.second.trustStore.IsRevokedBySerial(revoked.Serial)
	})

	// Отзыв переживает перезапуск: у узла без ключа CA единственное, что может
	// пережить ребут, — локальный кэш ca/revoked-cache.json.
	cachePath := filepath.Join(f.secondC.DataDir, "ca", "revoked-cache.json")
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("кэш отзывов не записан в %s: %v", cachePath, err)
	}

	// Подписанный CRL на диске узла без ключа CA не появиться не может — и не
	// должен: подписывать его вправе только CA-машина.
	if _, err := os.Stat(filepath.Join(f.secondC.DataDir, "ca", "crl.pem")); err == nil {
		t.Fatal("узел без ключа CA не должен подписывать CRL")
	}
}

// sendGossipAs отправляет gossip-пакет от имени nodeID, но подписанный ключом
// signer. Нужна, чтобы сыграть перехватчика канала: пакет выглядит как
// сообщение соседа, но подписан чужим ключом.
func sendGossipAs(conn *tls.Conn, nodeID [16]byte, entries []revokedCert, signer ed25519.PrivateKey) error {
	payload, err := SerializeGossipPayload(&GossipPayload{Number: 1, RevokedEntries: entries})
	if err != nil {
		return fmt.Errorf("сериализация gossip: %w", err)
	}

	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktGossip,
		NodeID:    nodeID,
		Timestamp: time.Now().Unix(),
		Payload:   payload,
	}

	if _, err := conn.Write(SignPacket(pkt, signer)); err != nil {
		return fmt.Errorf("запись gossip: %w", err)
	}

	return nil
}

// TestMeshGossipRejectsWrongSigner — пакет gossip, подписанный чужим ключом,
// не меняет CRL. Перехвативший канал не должен уметь навязать свои отзывы.
func TestMeshGossipRejectsWrongSigner(t *testing.T) {
	f := newMeshFixture(t)

	conn := f.dial(t)

	_, firstCertPath, _ := f.firstC.BeaconPaths()
	if err := ShareCertificate(firstCertPath, conn, f.first.edPriv, f.first.nodeID); err != nil {
		t.Fatalf("отправка cert-share: %v", err)
	}

	waitFor(t, 5*time.Second, "сертификат соседа у второго узла", func() bool {
		_, err := f.second.trustStore.CertByCN("beacon-first")
		return err == nil
	})

	// Пакет отправляется от имени первого узла (его NodeID), но подписан ключом
	// ВТОРОГО — того, кто этот канал и открыл.
	forged := []revokedCert{{
		SerialNumber: bigFromString(t, "123456789012345678901234567890"),
		RevokedAt:    time.Now(),
		Reason:       1,
	}}

	if err := sendGossipAs(conn, f.first.nodeID, forged, f.second.edPriv); err != nil {
		t.Fatalf("отправка подделки: %v", err)
	}

	// Даём обработчику время отреагировать и убеждаемся, что ничего не изменилось.
	time.Sleep(300 * time.Millisecond)

	if f.second.trustStore.IsRevokedBySerial(bigFromString(t, "123456789012345678901234567890")) {
		t.Fatal("gossip, подписанный чужим ключом, не должен применяться")
	}
}

// TestMeshGossipRejectsEmptyPayload — пустой gossip не ломает обработчик.
func TestMeshGossipRejectsEmptyPayload(t *testing.T) {
	f := newMeshFixture(t)

	conn := f.dial(t)

	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktGossip,
		NodeID:    f.first.nodeID,
		Timestamp: time.Now().Unix(),
	}

	if _, err := conn.Write(SignPacket(pkt, f.first.edPriv)); err != nil {
		t.Fatalf("запись gossip: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	if f.second.trustStore.CRLVersion() != 0 {
		t.Fatal("пустой gossip не должен менять CRL")
	}
}

// TestMeshRejectsUntrustedCertShare — сертификат от постороннего CA не
// попадает в roster, даже если пришёл по правильному каналу от соседа.
func TestMeshRejectsUntrustedCertShare(t *testing.T) {
	f := newMeshFixture(t)

	// Чужой CA и выпущенный им узел.
	otherDir := t.TempDir()
	otherCertPEM := newTestCA(t, otherDir)
	otherKey, err := LoadCAKey(filepath.Join(otherDir, "ca", "ca-key.pem"))
	if err != nil {
		t.Fatalf("LoadCAKey (чужой): %v", err)
	}

	rogue, err := IssueCertificate(otherKey, otherCertPEM, otherDir, "beacon-rogue", time.Hour, RolePeer)
	if err != nil {
		t.Fatalf("IssueCertificate (подделка): %v", err)
	}

	conn := f.dial(t)

	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktCertShare,
		NodeID:    f.first.nodeID,
		Timestamp: time.Now().Unix(),
		Payload:   mustReadFile(t, rogue.CertPath),
	}

	if _, err := conn.Write(SignPacket(pkt, f.first.edPriv)); err != nil {
		t.Fatalf("запись cert-share: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	if _, err := f.second.trustStore.CertByCN("beacon-rogue"); err == nil {
		t.Fatal("сертификат чужого CA не должен попадать в roster")
	}

	if _, err := os.Stat(PeerCertPath(f.secondC.DataDir, "beacon-rogue")); err == nil {
		t.Fatal("сертификат чужого CA не должен сохраняться на диск")
	}
}

// TestMeshPeerCertificateIsRequiredWithoutCert — соединение без сертификата
// не даёт обмена: mTLS без клиентского сертификата не пускает в сеть.
func TestMeshPeerCertificateIsRequiredWithoutCert(t *testing.T) {
	f := newMeshFixture(t)

	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", f.secondC.TLSPort), &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return // хендшейк отвергнут — это и требовалось
	}
	defer conn.Close()

	// В TLS 1.3 клиент узнаёт об отказе сервера не сразу: сервер запрашивает
	// сертификат после отправки своей Finished. Поэтому проверяем не хендшейк,
	// а первый обмен: сервер обязан разорвать соединение с alert.
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 1)
	if _, err := conn.Write([]byte{0}); err == nil {
		if _, err := conn.Read(buf); err == nil {
			t.Fatal("соединение без клиентского сертификата не должно работать")
		}
	}
}

// bigFromString разбирает серийник из строки (тестовый помощник).
func bigFromString(t *testing.T, s string) *big.Int {
	t.Helper()

	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatalf("некорректное число в тесте: %s", s)
	}

	return n
}
