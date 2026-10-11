package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// roleCert выпускает сертификат заданной роли через полноценный IssueCertificate.
func roleCert(t *testing.T, dir string, caKey *ecdsa.PrivateKey, caCertPEM []byte,
	cn string, role CertificateRole) *IssuedNode {
	t.Helper()

	issued, err := IssueCertificate(caKey, caCertPEM, dir, cn, time.Hour, role)
	if err != nil {
		t.Fatalf("IssueCertificate(%s, %v): %v", cn, role, err)
	}
	return issued
}

// newSSHServerForTest собирает SSH-сервер с доверенным сертификатом.
//
// SSH-серверу нужен host-ключ самого узла, поэтому выдаётся сертификат и на
// него: NewSSHServer читает key.pem и cert.pem из DataDir/<NodeName>.
func newSSHServerForTest(t *testing.T, cfg *Config, certs ...*x509.Certificate) *SSHServer {
	t.Helper()

	caKey, caCertPEM, err := GenerateCA(cfg.DataDir, DefaultCALifetime)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	caCert, err := LoadCACert(cfg.DataDir + "/ca/ca-cert.pem")
	if err != nil {
		t.Fatalf("LoadCACert: %v", err)
	}

	// Сертификат самому узлу — его ключ станет SSH host key.
	roleCert(t, cfg.DataDir, caKey, caCertPEM, cfg.NodeName, RoleServer)

	ts := &TrustStore{
		caPool:       x509.NewCertPool(),
		caCert:       caCert,
		trustedCerts: certs,
		ed25519Keys:  make(map[[16]byte]ed25519.PublicKey),
		crl: &CRLStore{
			revoked:  make(map[string]revokedCert),
			diskPath: filepath.Join(cfg.DataDir, "ca", "crl.pem"),
			caCert:   caCert,
			caKey:    caKey,
		},
	}
	ts.caPool.AddCert(caCert)

	srv, err := NewSSHServer(cfg, ts)
	if err != nil {
		t.Fatalf("NewSSHServer: %v", err)
	}

	return srv
}

// TestPeerRoleCannotLogin — регресс на главную дыру фазы 2.
//
// До разделения ролей любой выданный сертификат давал shell на всех узлах:
// компрометация одного маячка означала root на всех остальных.
func TestPeerRoleCannotLogin(t *testing.T) {
	dir := t.TempDir()

	_, caCertPEM, caErr := GenerateCA(dir, DefaultCALifetime)
	if caErr != nil {
		t.Fatalf("GenerateCA: %v", caErr)
	}
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	peer := roleCert(t, dir, caKey, caCertPEM, "beacon-peer", RolePeer)
	cert, err := loadCertPEM(peer.CertPath)
	if err != nil {
		t.Fatalf("загрузка сертификата: %v", err)
	}

	cfg := DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.NodeName = "beacon-target"
	cfg.SSHAllowCNs = []string{"beacon-peer"}

	srv := newSSHServerForTest(t, cfg, cert)

	sshKey, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}

	_, err = srv.authorize(testConnMeta{}, sshKey)
	if err == nil {
		t.Fatal("сертификат роли peer не должен получать SSH-доступ")
	}
}

// TestServerRoleCanLogin — серверная роль проходит, если CN разрешён.
func TestServerRoleCanLogin(t *testing.T) {
	dir := t.TempDir()

	_, caCertPEM, caErr := GenerateCA(dir, DefaultCALifetime)
	if caErr != nil {
		t.Fatalf("GenerateCA: %v", caErr)
	}
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	admin := roleCert(t, dir, caKey, caCertPEM, "beacon-admin", RoleServer)
	cert, err := loadCertPEM(admin.CertPath)
	if err != nil {
		t.Fatalf("загрузка сертификата: %v", err)
	}

	cfg := DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.NodeName = "beacon-target"
	cfg.SSHAllowCNs = []string{"beacon-admin"}

	srv := newSSHServerForTest(t, cfg, cert)

	sshKey, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}

	perms, err := srv.authorize(testConnMeta{}, sshKey)
	if err != nil {
		t.Fatalf("серверная роль с разрешённым CN должна проходить: %v", err)
	}
	if perms.Extensions["pubkey-cn"] != "beacon-admin" {
		t.Fatalf("не тот CN в разрешениях: %q", perms.Extensions["pubkey-cn"])
	}
}

// TestEmptyAllowlistDeniesAll — без -ssh-allow не пускает никого, кроме себя.
func TestEmptyAllowlistDeniesAll(t *testing.T) {
	dir := t.TempDir()

	_, caCertPEM, caErr := GenerateCA(dir, DefaultCALifetime)
	if caErr != nil {
		t.Fatalf("GenerateCA: %v", caErr)
	}
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	admin := roleCert(t, dir, caKey, caCertPEM, "beacon-admin", RoleServer)
	cert, _ := loadCertPEM(admin.CertPath)

	cfg := DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.NodeName = "beacon-target"
	// Allowlist намеренно пустой.

	srv := newSSHServerForTest(t, cfg, cert)

	sshKey, _ := ssh.NewPublicKey(cert.PublicKey)

	if _, err := srv.authorize(testConnMeta{}, sshKey); err == nil {
		t.Fatal("пустой allowlist должен означать отказ всем")
	}

	// Собственный CN всё ещё пускать нужно: иначе владелец не зайдёт на свой
	// узел, пока не добавит себя в список.
	self := roleCert(t, dir, caKey, caCertPEM, "beacon-target", RoleServer)
	selfCert, _ := loadCertPEM(self.CertPath)

	cfg2 := DefaultConfig()
	cfg2.NodeName = "beacon-target"
	srv2 := newSSHServerForTest(t, cfg2, selfCert)

	selfKey, _ := ssh.NewPublicKey(selfCert.PublicKey)
	if _, err := srv2.authorize(testConnMeta{}, selfKey); err != nil {
		t.Fatalf("собственный CN должен проходить без allowlist: %v", err)
	}
}

// TestSSHDisabledByDefault — SSH не поднимается без явного -ssh.
func TestSSHDisabledByDefault(t *testing.T) {
	dir := t.TempDir()

	_, caCertPEM, err := GenerateCA(dir, DefaultCALifetime)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	issued := roleCert(t, dir, caKey, caCertPEM, "beacon-node", RoleServer)

	cfg := DefaultConfig()
	cfg.DataDir = dir
	cfg.NodeName = "beacon-node"
	cfg.SSHEnabled = false // ровно как DefaultConfig
	cfg.SSHPort = 0
	cfg.TLSKeyPath = issued.KeyPath
	cfg.TLSCertPath = issued.CertPath

	node, err := NewBeaconNode(cfg)
	if err != nil {
		t.Fatalf("NewBeaconNode: %v", err)
	}

	// Не запускаем Listen-ы полностью — достаточно проверить решение.
	if node.config.SSHEnabled {
		t.Fatal("SSH должен быть выключен по умолчанию")
	}

	// SSH-сервер не должен быть создан.
	if node.sshServer != nil {
		t.Fatal("SSH-сервер не должен создаваться при SSHEnabled=false")
	}
}

// TestCommandWhitelist — whitelist сверяет команду целиком, а не по подстроке.
func TestCommandWhitelist(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.NodeName = "beacon-target"
	cfg.SSHAllowCommands = []string{"uname -a"}

	srv := newSSHServerForTest(t, cfg)

	// Ровно та же команда — можно.
	if !srv.allowCommand("uname -a") {
		t.Fatal("разрешённая команда должна проходить")
	}

	// Та же команда с добавлением — нет. Иначе whitelist обходится бы
	// приписыванием «; rm -rf /».
	if srv.allowCommand("uname -a; rm -rf /") {
		t.Fatal("дополнение к разрешённой команде должно отвергаться")
	}
	if srv.allowCommand("rm -rf /") {
		t.Fatal("неразрешённая команда должна отвергаться")
	}

	// Пустой список = без ограничений (включение whitelist — явное действие).
	cfg2 := DefaultConfig()
	srv2 := newSSHServerForTest(t, cfg2)
	if !srv2.allowCommand("что угодно") {
		t.Fatal("пустой whitelist должен разрешать всё")
	}
}

// TestSplitAndTrim — разбор списков из флагов.
func TestSplitAndTrim(t *testing.T) {
	got := splitAndTrim("beacon-a, beacon-b ,,")
	if len(got) != 2 {
		t.Fatalf("ожидалось 2 элемента, получено %d: %v", len(got), got)
	}
	if got[0] != "beacon-a" || got[1] != "beacon-b" {
		t.Fatalf("пробелы не обработаны: %v", got)
	}

	if len(splitAndTrim("")) != 0 {
		t.Fatal("пустая строка должна давать пустой список")
	}
	if len(splitAndTrim("  ")) != 0 {
		t.Fatal("строка из пробелов должна давать пустой список")
	}
}

// TestParseRole — разбор роли из флага.
func TestParseRole(t *testing.T) {
	server, err := ParseRole("server")
	if err != nil {
		t.Fatalf("ParseRole(server): %v", err)
	}
	if server != RoleServer {
		t.Fatal("server должен разбираться в RoleServer")
	}

	peer, err := ParseRole("peer")
	if err != nil {
		t.Fatalf("ParseRole(peer): %v", err)
	}
	if peer != RolePeer {
		t.Fatal("peer должен разбираться в RolePeer")
	}

	// Пустая строка — тоже peer: роль по умолчанию.
	empty, err := ParseRole("")
	if err != nil || empty != RolePeer {
		t.Fatal("пустая роль должна означать peer")
	}

	if _, err := ParseRole("суперпользователь"); err == nil {
		t.Fatal("некорректная роль должна отвергаться")
	}
}

// TestServerRoleGetsBothEKU — серверный сертификат пригоден для обеих сторон,
// клиентский — только для клиента. Без этого клиентский сертификат можно было
// бы использовать для приёма mTLS.
func TestServerRoleGetsBothEKU(t *testing.T) {
	dir := t.TempDir()

	_, caCertPEM, err := GenerateCA(dir, DefaultCALifetime)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	server := roleCert(t, dir, caKey, caCertPEM, "beacon-srv", RoleServer)
	serverCert, _ := loadCertPEM(server.CertPath)

	if !hasServerRole(serverCert) {
		t.Fatal("серверный сертификат должен иметь ServerAuth")
	}
	if !hasClientRole(serverCert) {
		t.Fatal("серверный сертификат должен иметь и ClientAuth")
	}

	peer := roleCert(t, dir, caKey, caCertPEM, "beacon-cli", RolePeer)
	peerCert, _ := loadCertPEM(peer.CertPath)

	if hasServerRole(peerCert) {
		t.Fatal("клиентский сертификат не должен иметь ServerAuth")
	}
	if !hasClientRole(peerCert) {
		t.Fatal("клиентский сертификат должен иметь ClientAuth")
	}
}

// hasClientRole проверяет наличие ClientAuth в EKU.
func hasClientRole(cert *x509.Certificate) bool {
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

// testConnMeta — минимальная реализация ssh.ConnMetadata для тестов authorize.
type testConnMeta struct{}

func (testConnMeta) User() string          { return "beacon" }
func (testConnMeta) SessionID() []byte     { return []byte("test-session") }
func (testConnMeta) ClientVersion() []byte { return []byte("SSH-2.0-test") }
func (testConnMeta) ServerVersion() []byte { return []byte("SSH-2.0-NetworkBeacons") }
func (testConnMeta) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}
func (testConnMeta) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}
}
