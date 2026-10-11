package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		// CRLSign обязателен: без него x509.CreateRevocationList отказывается
		// подписывать CRL, и тесты отзыва были бы невозможны.
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return key, cert, pool
}

// testCertSetup генерирует тестовый сертификат и возвращает конфиг для SSH.
func testCertSetup(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, cn string, revoke bool) (*Config, *TrustStore) {
	t.Helper()
	dir := t.TempDir()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	ski := make([]byte, 16)
	rand.Read(ski)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		SubjectKeyId: ski,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Создаём структуру директорий как у реального маячка
	nodeDir := dir + "/beacon-test"
	os.MkdirAll(nodeDir, 0700)
	os.MkdirAll(dir+"/ca", 0700)
	os.WriteFile(nodeDir+"/key.pem", keyPEM, 0600)
	os.WriteFile(nodeDir+"/cert.pem", certPEM, 0644)

	// Копируем CA-сертификат
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	os.WriteFile(dir+"/ca/ca-cert.pem", caCertPEM, 0644)

	// Создаём TrustStore с CA и доверенным сертификатом маячка
	beaconCert, _ := x509.ParseCertificate(certDER)

	ts := &TrustStore{
		caPool:       x509.NewCertPool(),
		caCert:       caCert,
		trustedCerts: []*x509.Certificate{beaconCert},
		ed25519Keys:  make(map[[16]byte]ed25519.PublicKey),
		crl: &CRLStore{
			revoked:  make(map[string]revokedCert),
			diskPath: dir + "/ca/crl.pem",
			caCert:   caCert,
			caKey:    caKey,
		},
	}
	ts.caPool.AddCert(caCert)

	if revoke {
		if err := ts.Revoke(beaconCert.SerialNumber, 1); err != nil {
			t.Fatalf("отзыв: %v", err)
		}
	}

	cfg := &Config{
		BindAddr:       "127.0.0.1",
		SSHPort:        0,
		SSHMaxConns:    5,
		SSHIdleTimeout: time.Minute,
		DataDir:        dir,
		NodeName:       "beacon-test",
	}

	return cfg, ts
}

// testSSHDial вспомогательная функция для подключения к SSH-серверу.
func testSSHDial(t *testing.T, cfg *Config, ts *TrustStore) (*SSHServer, *ssh.Client) {
	t.Helper()

	srv, err := NewSSHServer(cfg, ts)
	if err != nil {
		t.Fatalf("NewSSHServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	keyPath := cfg.DataDir + "/beacon-test/key.pem"
	certPath := cfg.DataDir + "/beacon-test/cert.pem"
	signer, err := createSSHCertSigner(keyPath, certPath)
	if err != nil {
		t.Fatalf("createSSHCertSigner: %v", err)
	}

	sshCfg := &ssh.ClientConfig{
		User: "test",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.SSHPort)
	conn, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		t.Fatalf("SSH Dial: %v", err)
	}

	return srv, conn
}

func TestSSHValidCert(t *testing.T) {
	caKey, caCert, _ := testCA(t)
	cfg, ts := testCertSetup(t, caKey, caCert, "beacon-test", false)

	srv, conn := testSSHDial(t, cfg, ts)
	defer conn.Close()
	defer srv.Stop()

	t.Log("SSH-соединение с валидным сертификатом установлена")
}

func TestSSHRevokedCert(t *testing.T) {
	caKey, caCert, _ := testCA(t)
	cfg, ts := testCertSetup(t, caKey, caCert, "beacon-revoked", true)

	srv, err := NewSSHServer(cfg, ts)
	if err != nil {
		t.Fatalf("NewSSHServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	keyPath := cfg.DataDir + "/beacon-test/key.pem"
	certPath := cfg.DataDir + "/beacon-test/cert.pem"
	signer, _ := createSSHCertSigner(keyPath, certPath)

	sshCfg := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.SSHPort)
	_, err = ssh.Dial("tcp", addr, sshCfg)
	if err == nil {
		t.Fatal("ожидалась ошибка при подключении с отозванным сертификатом")
	}
	t.Logf("Отклонено как ожидалось: %v", err)
}

func TestSSHSelfSignedCert(t *testing.T) {
	dir := t.TempDir()
	_, caCert, _ := testCA(t)

	// Самоподписанный сертификат (не от нашего CA)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	selfTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "self-signed"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, selfTemplate, selfTemplate, &key.PublicKey, key)

	nodeDir := dir + "/beacon-test"
	os.MkdirAll(nodeDir, 0700)
	os.MkdirAll(dir+"/ca", 0700)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	os.WriteFile(nodeDir+"/key.pem", keyPEM, 0600)
	os.WriteFile(nodeDir+"/cert.pem", certPEM, 0644)

	// CA-сертификат для TrustStore (отличается от самоподписанного)
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	os.WriteFile(dir+"/ca/ca-cert.pem", caCertPEM, 0644)

	ts := &TrustStore{
		caPool:      x509.NewCertPool(),
		caCert:      caCert,
		ed25519Keys: make(map[[16]byte]ed25519.PublicKey),
		crl: &CRLStore{
			revoked:  make(map[string]revokedCert),
			diskPath: dir + "/ca/crl.pem",
			caCert:   caCert,
		},
	}
	ts.caPool.AddCert(caCert)

	cfg := &Config{
		BindAddr: "127.0.0.1", SSHPort: 0, SSHMaxConns: 5,
		SSHIdleTimeout: time.Minute, DataDir: dir, NodeName: "beacon-test",
	}

	srv, err := NewSSHServer(cfg, ts)
	if err != nil {
		t.Fatalf("NewSSHServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	signer, _ := createSSHCertSigner(nodeDir+"/key.pem", nodeDir+"/cert.pem")
	sshCfg := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.SSHPort)
	_, err = ssh.Dial("tcp", addr, sshCfg)
	if err == nil {
		t.Fatal("ожидалась ошибка для самоподписанного сертификата")
	}
	t.Logf("Отклонено: %v", err)
}

func TestSSHExec(t *testing.T) {
	caKey, caCert, _ := testCA(t)
	cfg, ts := testCertSetup(t, caKey, caCert, "beacon-exec", false)

	srv, conn := testSSHDial(t, cfg, ts)
	defer conn.Close()
	defer srv.Stop()

	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput("echo hello-beacon")
	if err != nil {
		t.Fatalf("CombinedOutput: %v", err)
	}
	if string(output) != "hello-beacon\n" {
		t.Fatalf("ожидалось 'hello-beacon\\n', получено '%s'", string(output))
	}
	t.Logf("Exec: %s", string(output))
}
