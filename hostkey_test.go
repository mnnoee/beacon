package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// makeSSHCert выпускает сертификат с указанным CN и сроком действия.
func makeSSHCert(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, cn string, notAfter time.Time) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("генерация ключа: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("создание сертификата: %v", err)
	}

	cert, _ := x509.ParseCertificate(certDER)
	return cert
}

// trustStoreWithCerts собирает TrustStore с заданными доверенными сертификатами.
//
// Ключ CA обязателен: без него CRL нечем подписать, а значит отзыв был бы
// невозможен, и тесты проверки отзыва падали бы не по той причине.
func trustStoreWithCerts(t *testing.T, caCert *x509.Certificate, certs ...*x509.Certificate) *TrustStore {
	t.Helper()

	dir := t.TempDir()
	caCertPath := filepath.Join(dir, "ca-cert.pem")
	caKeyPath := filepath.Join(dir, "ca-key.pem")

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	if err := os.WriteFile(caCertPath, pemBytes, 0644); err != nil {
		t.Fatalf("запись CA-сертификата: %v", err)
	}

	caKey := mustECDSAKey(t)
	keyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		t.Fatalf("маршализация ключа: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(caKeyPath, keyPEM, 0600); err != nil {
		t.Fatalf("запись ключа CA: %v", err)
	}

	store, err := LoadCRLStore(filepath.Join(dir, "crl.pem"), caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("LoadCRLStore: %v", err)
	}

	ts := &TrustStore{
		caPool:       x509.NewCertPool(),
		caCert:       caCert,
		trustedCerts: certs,
		ed25519Keys:  make(map[[16]byte]ed25519.PublicKey),
		crl:          store,
	}
	ts.caPool.AddCert(caCert)

	return ts
}

// TestVerifyHostKeyAcceptsKnownNode — host-ключ известного узла принимается.
func TestVerifyHostKeyAcceptsKnownNode(t *testing.T) {
	caKey, caCert, _ := testCA(t)

	cert := makeSSHCert(t, caKey, caCert, "beacon-nas", time.Now().Add(time.Hour))
	ts := trustStoreWithCerts(t, caCert, cert)

	sshKey, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}

	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.4"), Port: 2222}

	if err := ts.VerifyHostKey("", addr, sshKey); err != nil {
		t.Fatalf("host-ключ известного узла должен приниматься: %v", err)
	}
}

// TestVerifyHostKeyRejectsForeignKey — ключ, не принадлежащий ни одному
// сертификату нашего CA, отвергается. Это и есть защита от MITM.
func TestVerifyHostKeyRejectsForeignKey(t *testing.T) {
	caKey, caCert, _ := testCA(t)

	known := makeSSHCert(t, caKey, caCert, "beacon-nas", time.Now().Add(time.Hour))
	ts := trustStoreWithCerts(t, caCert, known)

	// Ключ атакующего — валидный SSH-ключ, но не наш.
	attackerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attackerPub, err := ssh.NewPublicKey(&attackerKey.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}

	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.99"), Port: 2222}

	err = ts.VerifyHostKey("", addr, attackerPub)
	if err == nil {
		t.Fatal("чужой host-ключ должен отвергаться")
	}
}

// TestVerifyHostKeyRejectsOtherCA — сертификат от другого CA не подходит,
// даже если ключ сам по себе корректен.
func TestVerifyHostKeyRejectsOtherCA(t *testing.T) {
	_, ourCA, _ := testCA(t)

	// Подпись чужим CA: ключ и сертификат должны соответствовать друг другу.
	otherCAKey, otherCA, _ := testCA(t)
	foreign := makeSSHCert(t, otherCAKey, otherCA, "beacon-rogue", time.Now().Add(time.Hour))

	ts := trustStoreWithCerts(t, ourCA, foreign)

	sshKey, err := ssh.NewPublicKey(foreign.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}

	if err := ts.VerifyHostKey("", &net.TCPAddr{}, sshKey); err == nil {
		t.Fatal("сертификат чужого CA должен отвергаться")
	}
}

// TestVerifyHostKeyRejectsRevoked — отозванный узел не проходит проверку
// даже при верном ключе.
func TestVerifyHostKeyRejectsRevoked(t *testing.T) {
	caKey, caCert, _ := testCA(t)

	cert := makeSSHCert(t, caKey, caCert, "beacon-bad", time.Now().Add(time.Hour))
	ts := trustStoreWithCerts(t, caCert, cert)

	sshKey, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}

	addr := &net.TCPAddr{}

	// До отзыва — принимается.
	if err := ts.VerifyHostKey("", addr, sshKey); err != nil {
		t.Fatalf("до отзыва host-ключ должен приниматься: %v", err)
	}

	if err := ts.crl.Revoke(cert.SerialNumber, 1); err != nil {
		t.Fatalf("отзыв: %v", err)
	}

	// После отзыва — нет.
	if err := ts.VerifyHostKey("", addr, sshKey); err == nil {
		t.Fatal("отозванный узел должен отвергаться")
	}
}

// TestVerifyHostKeyRejectsExpired — просроченный сертификат не подходит.
func TestVerifyHostKeyRejectsExpired(t *testing.T) {
	caKey, caCert, _ := testCA(t)

	expired := makeSSHCert(t, caKey, caCert, "beacon-old", time.Now().Add(-time.Hour))
	ts := trustStoreWithCerts(t, caCert, expired)

	sshKey, err := ssh.NewPublicKey(expired.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}

	if err := ts.VerifyHostKey("", &net.TCPAddr{}, sshKey); err == nil {
		t.Fatal("просроченный сертификат должен отвергаться")
	}
}

// TestVerifyHostKeyRejectsNil — пустой ключ не должен проходить.
func TestVerifyHostKeyRejectsNil(t *testing.T) {
	_, caCert, _ := testCA(t)
	ts := trustStoreWithCerts(t, caCert)

	if err := ts.VerifyHostKey("", &net.TCPAddr{}, nil); err == nil {
		t.Fatal("пустой host-ключ должен отвергаться")
	}
}

// TestSSHClientRefusesWithoutTrustStore — клиент без TrustStore обязан
// отказаться подключаться, а не отключить проверку host-ключа.
func TestSSHClientRefusesWithoutTrustStore(t *testing.T) {
	dir := t.TempDir()

	cfg := DefaultConfig()
	cfg.DataDir = dir
	cfg.NodeName = "beacon-laptop"

	client := NewSSHClient(cfg)
	// TrustStore намеренно не установлен.

	err := client.Connect("127.0.0.1:1", "")
	if err == nil {
		t.Fatal("клиент без TrustStore обязан отказаться от подключения")
	}
	if !strings.Contains(err.Error(), "TrustStore") {
		t.Fatalf("ошибка должна объяснять причину, получено: %v", err)
	}
}

// mustECDSAKey создаёт новый ключ CA для подделки.
func mustECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("генерация ключа: %v", err)
	}
	return key
}
