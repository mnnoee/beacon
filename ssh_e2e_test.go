package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// freeTCPPort возвращает свободный TCP-порт на loopback.
func freeTCPPort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("резервирование TCP-порта: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	return port
}

// captureStdout выполняет fn и возвращает всё, что он вывел в stdout.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("создание pipe: %v", err)
	}

	original := os.Stdout
	os.Stdout = w

	fnErr := fn()

	w.Close()
	os.Stdout = original

	out, readErr := io.ReadAll(r)
	r.Close()
	if readErr != nil {
		t.Fatalf("чтение вывода: %v", readErr)
	}

	return string(out), fnErr
}

// sshFixture — два узла под одним CA, разложенные как в живой сети: сертификаты
// соседей лежат в peers/ (их доставил cert-share по mTLS), иначе узлы не знают
// друг о друге и не способны ни разрешить имя, ни авторизовать SSH.
type sshFixture struct {
	caKeyPEM  []byte
	caCertPEM []byte

	serverDir  string
	clientDir  string
	serverCert string // путь к cert.pem соседа
	clientCert string // путь к cert.pem клиента
}

// newSSHFixture выпускает оба сертификата и раскладывает их так, как их
// раскладывает работающая сеть.
func newSSHFixture(t *testing.T) *sshFixture {
	t.Helper()

	serverDir := t.TempDir()
	caCertPEM := newTestCA(t, serverDir)
	caKeyPEM := mustReadFile(t, filepath.Join(serverDir, "ca", "ca-key.pem"))
	caKey, err := LoadCAKey(filepath.Join(serverDir, "ca", "ca-key.pem"))
	if err != nil {
		t.Fatalf("LoadCAKey: %v", err)
	}

	server, err := IssueCertificate(caKey, caCertPEM, serverDir, "beacon-nas", time.Hour, RoleServer)
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
	// Клиент — тоже серверный узел: SSH-доступ получают только сертификаты
	// роли server (решение фазы 2, см. SSHServer.authorize).
	client, err := IssueCertificate(caKey, caCertPEM, clientDir, "beacon-cli", time.Hour, RoleServer)
	if err != nil {
		t.Fatalf("IssueCertificate (клиент): %v", err)
	}

	// Обмен сертификатами: каждый кладёт сертификат соседа себе в peers/.
	if err := os.MkdirAll(PeersDir(clientDir), 0700); err != nil {
		t.Fatalf("MkdirAll peers (клиент): %v", err)
	}
	if err := os.WriteFile(PeerCertPath(clientDir, "beacon-nas"), mustReadFile(t, server.CertPath), 0644); err != nil {
		t.Fatalf("сертификат соседа клиенту: %v", err)
	}

	if err := os.MkdirAll(PeersDir(serverDir), 0700); err != nil {
		t.Fatalf("MkdirAll peers (сосед): %v", err)
	}
	if err := os.WriteFile(PeerCertPath(serverDir, "beacon-cli"), mustReadFile(t, client.CertPath), 0644); err != nil {
		t.Fatalf("сертификат клиента соседу: %v", err)
	}

	return &sshFixture{
		caKeyPEM:   caKeyPEM,
		caCertPEM:  caCertPEM,
		serverDir:  serverDir,
		clientDir:  clientDir,
		serverCert: server.CertPath,
		clientCert: client.CertPath,
	}
}

// startServer поднимает маячок-сосед с включённым SSH-сервером.
func (f *sshFixture) startServer(t *testing.T) *Config {
	t.Helper()

	cfg := DefaultConfig()
	cfg.DataDir = f.serverDir
	cfg.NodeName = "beacon-nas"
	cfg.BindAddr = "127.0.0.1"
	cfg.BroadcastAddr = "127.255.255.255"
	cfg.DiscoveryPort = freeUDPPort(t)
	cfg.TLSPort = freeTCPPort(t)
	cfg.SSHPort = 0 // случайный порт, реальный подставит SSHServer.Start
	cfg.SSHEnabled = true
	cfg.SSHAllowCNs = []string{"beacon-cli"}

	node, err := NewBeaconNode(cfg)
	if err != nil {
		t.Fatalf("NewBeaconNode: %v", err)
	}
	if err := node.Start(); err != nil {
		t.Fatalf("запуск соседа: %v", err)
	}
	t.Cleanup(node.Stop)

	if node.sshServer == nil {
		t.Fatal("SSH-сервер соседа не поднялся")
	}

	return cfg
}

// client собирает SSH-клиента с TrustStore клиентского каталога.
func (f *sshFixture) client(t *testing.T, serverCfg *Config) *SSHClient {
	t.Helper()

	ts, err := NewTrustStore(filepath.Join(f.clientDir, "ca", "ca-cert.pem"),
		filepath.Join(f.clientDir, "ca", "crl.pem"))
	if err != nil {
		t.Fatalf("NewTrustStore (клиент): %v", err)
	}

	cfg := DefaultConfig()
	cfg.DataDir = f.clientDir
	cfg.NodeName = "beacon-cli"
	cfg.BindAddr = "127.0.0.1"
	cfg.BroadcastAddr = serverCfg.BroadcastAddr
	cfg.DiscoveryPort = serverCfg.DiscoveryPort
	cfg.SSHPort = serverCfg.SSHPort

	c := NewSSHClient(cfg)
	c.SetTrustStore(ts)

	return c
}

// TestSSHConnectByNameEndToEnd — `beacon ssh <имя>` проходит весь путь: имя
// разрешается в адрес через discovery, host-ключ сверяется с сертификатом
// соседа, авторизация проходит по allowlist, команда выполняется на соседе.
//
// Это проверка блокера фазы 3: пока объявление уходило с отдельного сокета,
// сосед отвечал на уже закрытый порт, и имя не разрешалось никогда.
func TestSSHConnectByNameEndToEnd(t *testing.T) {
	f := newSSHFixture(t)
	serverCfg := f.startServer(t)

	out, err := captureStdout(t, func() error {
		return f.client(t, serverCfg).Connect("beacon-nas", "echo beacon-marker")
	})
	if err != nil {
		t.Fatalf("подключение по имени: %v", err)
	}

	if !strings.Contains(out, "beacon-marker") {
		t.Fatalf("команда не отработала на соседе, вывод: %q", out)
	}
}

// TestSSHConnectRejectsPeerRole — узел с сертификатом роли peer не получает
// SSH-доступ даже при корректной подписи и попадании в allowlist.
//
// Роли разведены осознанно: компрометация любого узла сети не должна давать
// shell на всех остальных, поэтому право входа выдаётся ролью server явно.
func TestSSHConnectRejectsPeerRole(t *testing.T) {
	f := newSSHFixture(t)

	// Перевыпускаем клиента с ролью peer и кладём новый сертификат соседу.
	caKey, err := LoadCAKey(filepath.Join(f.serverDir, "ca", "ca-key.pem"))
	if err != nil {
		t.Fatalf("LoadCAKey: %v", err)
	}

	peerDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(peerDir, "ca"), 0700); err != nil {
		t.Fatalf("MkdirAll ca: %v", err)
	}
	if err := os.WriteFile(filepath.Join(peerDir, "ca", "ca-cert.pem"), f.caCertPEM, 0644); err != nil {
		t.Fatalf("запись CA-сертификата: %v", err)
	}
	if _, err := IssueCertificate(caKey, f.caCertPEM, peerDir, "beacon-cli", time.Hour, RolePeer); err != nil {
		t.Fatalf("IssueCertificate (peer): %v", err)
	}
	if err := os.MkdirAll(PeersDir(peerDir), 0700); err != nil {
		t.Fatalf("MkdirAll peers: %v", err)
	}
	if err := os.WriteFile(PeerCertPath(peerDir, "beacon-nas"), mustReadFile(t, f.serverCert), 0644); err != nil {
		t.Fatalf("сертификат соседа клиенту: %v", err)
	}
	if err := os.WriteFile(PeerCertPath(f.serverDir, "beacon-cli"),
		mustReadFile(t, filepath.Join(peerDir, "beacon-cli", "cert.pem")), 0644); err != nil {
		t.Fatalf("сертификат peer-соседа серверу: %v", err)
	}

	// Сервер поднимаем после раскладки peers/, чтобы он перечитал сертификаты.
	serverCfg := f.startServer(t)

	ts, err := NewTrustStore(filepath.Join(peerDir, "ca", "ca-cert.pem"),
		filepath.Join(peerDir, "ca", "crl.pem"))
	if err != nil {
		t.Fatalf("NewTrustStore (peer): %v", err)
	}

	cfg := DefaultConfig()
	cfg.DataDir = peerDir
	cfg.NodeName = "beacon-cli"
	cfg.BindAddr = "127.0.0.1"
	cfg.BroadcastAddr = serverCfg.BroadcastAddr
	cfg.DiscoveryPort = serverCfg.DiscoveryPort
	cfg.SSHPort = serverCfg.SSHPort

	client := NewSSHClient(cfg)
	client.SetTrustStore(ts)

	if _, err := captureStdout(t, func() error {
		return client.Connect("beacon-nas", "echo beacon-marker")
	}); err == nil {
		t.Fatal("сертификат роли peer не должен получать SSH-доступ")
	}
}

// TestSSHConnectRejectsCNOutsideAllowlist — узел с валидным сертификатом, но не
// попавшим в -ssh-allow, доступа не получает.
func TestSSHConnectRejectsCNOutsideAllowlist(t *testing.T) {
	f := newSSHFixture(t)

	serverCfg := DefaultConfig()
	serverCfg.DataDir = f.serverDir
	serverCfg.NodeName = "beacon-nas"
	serverCfg.BindAddr = "127.0.0.1"
	serverCfg.BroadcastAddr = "127.255.255.255"
	serverCfg.DiscoveryPort = freeUDPPort(t)
	serverCfg.TLSPort = freeTCPPort(t)
	serverCfg.SSHPort = 0
	serverCfg.SSHEnabled = true
	serverCfg.SSHAllowCNs = []string{"beacon-другой"}

	node, err := NewBeaconNode(serverCfg)
	if err != nil {
		t.Fatalf("NewBeaconNode: %v", err)
	}
	if err := node.Start(); err != nil {
		t.Fatalf("запуск соседа: %v", err)
	}
	t.Cleanup(node.Stop)

	if _, err := captureStdout(t, func() error {
		return f.client(t, serverCfg).Connect("beacon-nas", "echo beacon-marker")
	}); err == nil {
		t.Fatal("CN вне allowlist не должен получать доступ")
	}
}

// TestSSHConnectRejectsForeignCA — сертификат соседа от чужого CA не проходит
// проверку нашего CA и не попадает в TrustStore: подключения не будет.
func TestSSHConnectRejectsForeignCA(t *testing.T) {
	f := newSSHFixture(t)
	serverCfg := f.startServer(t)

	// Клиент с чужим CA: его собственный сертификат выдан не нашему CA.
	otherCA := t.TempDir()
	otherCertPEM := newTestCA(t, otherCA)
	otherKey, err := LoadCAKey(filepath.Join(otherCA, "ca", "ca-key.pem"))
	if err != nil {
		t.Fatalf("LoadCAKey (чужой): %v", err)
	}

	rogueDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rogueDir, "ca"), 0700); err != nil {
		t.Fatalf("MkdirAll ca: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rogueDir, "ca", "ca-cert.pem"), otherCertPEM, 0644); err != nil {
		t.Fatalf("запись чужого CA: %v", err)
	}
	if _, err := IssueCertificate(otherKey, otherCertPEM, rogueDir, "beacon-cli", time.Hour, RolePeer); err != nil {
		t.Fatalf("IssueCertificate (подделка): %v", err)
	}
	if err := os.MkdirAll(PeersDir(rogueDir), 0700); err != nil {
		t.Fatalf("MkdirAll peers: %v", err)
	}
	if err := os.WriteFile(PeerCertPath(rogueDir, "beacon-nas"), mustReadFile(t, f.serverCert), 0644); err != nil {
		t.Fatalf("запись сертификата соседа: %v", err)
	}

	rogueTS, err := NewTrustStore(filepath.Join(rogueDir, "ca", "ca-cert.pem"),
		filepath.Join(rogueDir, "ca", "crl.pem"))
	if err != nil {
		t.Fatalf("NewTrustStore (подделка): %v", err)
	}

	cfg := DefaultConfig()
	cfg.DataDir = rogueDir
	cfg.NodeName = "beacon-cli"
	cfg.BindAddr = "127.0.0.1"
	cfg.BroadcastAddr = serverCfg.BroadcastAddr
	cfg.DiscoveryPort = serverCfg.DiscoveryPort
	cfg.SSHPort = serverCfg.SSHPort

	rogue := NewSSHClient(cfg)
	rogue.SetTrustStore(rogueTS)

	if _, err := captureStdout(t, func() error {
		return rogue.Connect("beacon-nas", "echo beacon-marker")
	}); err == nil {
		t.Fatal("узел с чужим CA не должен приниматься")
	}
}
