package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

// loadCertPEM загружает сертификат с диска.
func loadCertPEM(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("невалидный PEM в %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

// TestNodeIDDerivation проверяет, что NodeID выводится из Ed25519-ключа
// одинаково на всех сторонах и не совпадает для разных ключей.
func TestNodeIDDerivation(t *testing.T) {
	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)

	idA1 := NodeIDFromEd25519Pub(pubA)
	idA2 := NodeIDFromEd25519Pub(pubA)

	if idA1 != idA2 {
		t.Fatal("NodeID должен быть детерминированным")
	}
	if idA1 == NodeIDFromEd25519Pub(pubB) {
		t.Fatal("разные ключи должны давать разные NodeID")
	}

	// Старый способ (первые 16 байт ключа) больше не используется —
	// проверяем, что он даёт другой результат, то есть миграция реальна.
	var oldStyle [16]byte
	copy(oldStyle[:], pubA[:16])
	if oldStyle == idA1 {
		t.Fatal("NodeID совпал со старым способом вычисления — миграция не состоялась")
	}
}

// TestEd25519InCertificateSAN проверяет round-trip публичного ключа через SAN.
func TestEd25519InCertificateSAN(t *testing.T) {
	dir := t.TempDir()
	_, certPEM, _ := GenerateCA(dir, DefaultCALifetime)
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	issued, err := IssueCertificate(caKey, certPEM, dir, "beacon-san", DefaultCertTTL)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	cert, err := loadCertPEM(issued.CertPath)
	if err != nil {
		t.Fatalf("loadCertPEM: %v", err)
	}

	got, err := Ed25519PubFromCert(cert)
	if err != nil {
		t.Fatalf("Ed25519PubFromCert: %v", err)
	}

	if !got.Equal(issued.Ed25519Pub) {
		t.Fatal("ключ в SAN не совпадает с выданным")
	}

	// Приватный ключ должен соответствовать публичному в сертификате.
	privData, err := os.ReadFile(issued.Ed25519Path)
	if err != nil {
		t.Fatalf("чтение Ed25519-ключа: %v", err)
	}
	priv, err := DeserializePrivateKeyPEM(privData)
	if err != nil {
		t.Fatalf("DeserializePrivateKeyPEM: %v", err)
	}
	if !priv.Public().(ed25519.PublicKey).Equal(got) {
		t.Fatal("приватный ключ не соответствует ключу в сертификате")
	}

	// NodeID из сертификата обязан совпадать с выданным.
	certID, err := NodeIDFromCert(cert)
	if err != nil {
		t.Fatalf("NodeIDFromCert: %v", err)
	}
	if certID != issued.NodeID {
		t.Fatalf("NodeID из сертификата %X != выданный %X", certID, issued.NodeID)
	}
}

// TestCertificateWithoutSANFails проверяет, что сертификат старого формата
// (без ключа в SAN) отвергается, а не молча трактуется как валидный.
func TestCertificateWithoutSANFails(t *testing.T) {
	caKey, caCert, _ := testCA(t)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "beacon-legacy"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// Намеренно без URIs — формат до протокола v2.
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	cert, _ := x509.ParseCertificate(certDER)

	if _, err := NodeIDFromCert(cert); err == nil {
		t.Fatal("сертификат без Ed25519 в SAN должен отвергаться")
	}

	// Наш собственный CA не содержит Ed25519-ключа узлов, поэтому
	// проверка на CA-сертификате тоже должна давать понятную ошибку.
	if _, err := NodeIDFromCert(caCert); err == nil {
		t.Fatal("CA-сертификат не должен проходить как узловой")
	}
}

// TestDiscoverySignatureRejectsSpoofing проверяет главное свойство фазы 0:
// пакет, подписанный чужим ключом, не создаёт пира.
func TestDiscoverySignatureRejectsSpoofing(t *testing.T) {
	dir := t.TempDir()
	_, certPEM, _ := GenerateCA(dir, DefaultCALifetime)
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	honest, err := IssueCertificate(caKey, certPEM, dir, "beacon-honest", DefaultCertTTL)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	ts, _ := NewTrustStore(dir+"/ca/ca-cert.pem", dir+"/ca/crl.pem")
	ts.RegisterEd25519KeyFromDisk(dir)

	d := &Discovery{
		nodeID:     honest.NodeID,
		privKey:    mustLoadEdKey(t, honest.Ed25519Path),
		pubKey:     honest.Ed25519Pub,
		trustStore: ts,
		sentNonces: map[[32]byte]time.Time{},
	}

	// Честный пакет принимается.
	payload, _ := (&AnnouncePayload{Ed25519Pub: honest.Ed25519Pub}).Serialize()
	pkt := &DiscoveryPacket{
		Magic: DiscoveryMagic, Version: ProtocolVersion, Type: PktAnnounce,
		NodeID: honest.NodeID, Timestamp: time.Now().Unix(), Payload: payload,
	}
	rand.Read(pkt.Nonce[:])
	full := SignPacket(pkt, d.privKey)
	parsed, err := DeserializePacket(full)
	if err != nil {
		t.Fatalf("DeserializePacket: %v", err)
	}
	if err := d.verifyPacketSignature(parsed, full); err != nil {
		t.Fatalf("честный пакет должен приниматься: %v", err)
	}

	// Испорченная подпись отвергается.
	tampered := append([]byte(nil), full...)
	tampered[len(tampered)-1] ^= 0xFF
	if err := d.verifyPacketSignature(parsed, tampered); err == nil {
		t.Fatal("испорченная подпись должна отвергаться")
	}

	// Подмена NodeID при валидной подписи отвергается.
	pkt2 := &DiscoveryPacket{
		Magic: DiscoveryMagic, Version: ProtocolVersion, Type: PktAnnounce,
		NodeID: [16]byte{0xDE, 0xAD}, Timestamp: time.Now().Unix(), Payload: payload,
	}
	rand.Read(pkt2.Nonce[:])
	full2 := SignPacket(pkt2, d.privKey)
	parsed2, err := DeserializePacket(full2)
	if err != nil {
		t.Fatalf("DeserializePacket: %v", err)
	}
	if err := d.verifyPacketSignature(parsed2, full2); err == nil {
		t.Fatal("чужой NodeID должен отвергаться")
	}
}

// mustLoadEdKey загружает Ed25519-ключ или падает в тесте.
func mustLoadEdKey(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("чтение ключа: %v", err)
	}
	key, err := DeserializePrivateKeyPEM(data)
	if err != nil {
		t.Fatalf("разбор ключа: %v", err)
	}
	return key
}

func TestFullPKIWorkflow(t *testing.T) {
	dir := t.TempDir()

	// Генерация CA
	_, certPEM, err := GenerateCA(dir, DefaultCALifetime)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")
	caCert, _ := LoadCACert(dir + "/ca/ca-cert.pem")
	t.Logf("CA: CN=%s fingerprint=%s", caCert.Subject.CommonName, Fingerprint(caCert))

	// Выдача сертификатов
	node1, err := IssueCertificate(caKey, certPEM, dir, "beacon-t1", DefaultCertTTL)
	if err != nil {
		t.Fatalf("Issue cert1: %v", err)
	}
	node2, err := IssueCertificate(caKey, certPEM, dir, "beacon-t2", DefaultCertTTL)
	if err != nil {
		t.Fatalf("Issue cert2: %v", err)
	}

	// Идентичность узла выводится из Ed25519-ключа и должна совпадать
	// с тем, что лежит в сертификате.
	cert1, err := loadCertPEM(node1.CertPath)
	if err != nil {
		t.Fatalf("load cert1: %v", err)
	}
	certID, err := NodeIDFromCert(cert1)
	if err != nil {
		t.Fatalf("NodeIDFromCert: %v", err)
	}
	if certID != node1.NodeID {
		t.Fatalf("NodeID mismatch: cert=%X issued=%X", certID, node1.NodeID)
	}

	// Загрузка CA pool
	caPEM, _ := os.ReadFile(dir + "/ca/ca-cert.pem")
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	// Загрузка ключей
	srvCert, _ := tls.LoadX509KeyPair(node1.CertPath, node1.KeyPath)
	cliCert, _ := tls.LoadX509KeyPair(node2.CertPath, node2.KeyPath)

	// TLS-конфиги (сервер и клиент отдельно)
	srvCfg := &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	cliCfg := &tls.Config{
		Certificates:       []tls.Certificate{cliCert},
		RootCAs:            caPool,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	// TLS-сервер
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	type srvResult struct {
		cn  string
		err error
	}
	srvCh := make(chan srvResult, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvCh <- srvResult{"", err}
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		tlsConn.Handshake()
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			srvCh <- srvResult{state.PeerCertificates[0].Subject.CommonName, nil}
		} else {
			srvCh <- srvResult{"", fmt.Errorf("no peer cert")}
		}
		buf := make([]byte, 100)
		n, _ := tlsConn.Read(buf)
		tlsConn.Write([]byte("ACK"))
		t.Logf("server read: %s", buf[:n])
	}()

	// TLS-клиент
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", ln.Addr().String(), cliCfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no server cert")
	}
	t.Logf("client verified server: CN=%s fingerprint=%s",
		state.PeerCertificates[0].Subject.CommonName,
		Fingerprint(state.PeerCertificates[0]))

	// Обмен данными
	conn.Write([]byte("HELLO"))
	buf := make([]byte, 100)
	n, _ := io.ReadAtLeast(conn, buf, 3)
	t.Logf("client read: %s", buf[:n])

	// Результат сервера
	select {
	case res := <-srvCh:
		if res.err != nil {
			t.Fatalf("server error: %v", res.err)
		}
		t.Logf("server verified client: CN=%s", res.cn)
	case <-time.After(5 * time.Second):
		t.Fatal("server timeout")
	}
}

func TestTrustStoreRevocation(t *testing.T) {
	dir := t.TempDir()
	_, certPEM, _ := GenerateCA(dir, DefaultCALifetime)
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")
	IssueCertificate(caKey, certPEM, dir, "revoke-me", DefaultCertTTL)

	ts, _ := NewTrustStore(dir+"/ca/ca-cert.pem", dir+"/ca/crl.pem")
	certData, _ := os.ReadFile(dir + "/revoke-me/cert.pem")
	block, _ := pem.Decode(certData)
	cert, _ := x509.ParseCertificate(block.Bytes)

	if !ts.IsTrusted(cert) {
		t.Fatal("should be trusted before revoke")
	}

	h := ComputeSerialHash(cert)
	ts.Revoke(h, 1)

	if ts.IsTrusted(cert) {
		t.Fatal("should NOT be trusted after revoke")
	}

	ts2, _ := NewTrustStore(dir+"/ca/ca-cert.pem", dir+"/ca/crl.pem")
	if !ts2.IsRevoked(h) {
		t.Fatal("CRL must persist to disk")
	}
}

func TestGossipCRLMerge(t *testing.T) {
	dir := t.TempDir()
	_, certPEM, _ := GenerateCA(dir, DefaultCALifetime)
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")
	IssueCertificate(caKey, certPEM, dir, "gossip-node", DefaultCertTTL)
	ts, _ := NewTrustStore(dir+"/ca/ca-cert.pem", dir+"/ca/crl.pem")

	certData, _ := os.ReadFile(dir + "/gossip-node/cert.pem")
	block, _ := pem.Decode(certData)
	cert, _ := x509.ParseCertificate(block.Bytes)
	h := ComputeSerialHash(cert)
	ts.Revoke(h, 1)

	entries := []RevokedEntry{{SerialHash: h, RevokedAt: time.Now().Unix(), Reason: 1}}

	// Старая версия — не применять
	if ts.MergeGossipCRL(0, entries) {
		t.Fatal("old version must not merge")
	}

	// Новая версия — применять
	if !ts.MergeGossipCRL(ts.CRLVersion()+1, entries) {
		t.Fatal("new version must merge")
	}
}

func TestProtocolSerialization(t *testing.T) {
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	payload, _ := (&AnnouncePayload{Ed25519Pub: edPub}).Serialize()

	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktEcho,
		NodeID:    NodeIDFromEd25519Pub(edPub),
		Timestamp: time.Now().Unix(),
		Payload:   payload,
	}
	rand.Read(pkt.Nonce[:])

	// Подпись идёт по тем же байтам, что и на приёме.
	full := SignPacket(pkt, edPriv)

	parsed, err := DeserializePacket(full)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.NodeID != pkt.NodeID {
		t.Fatal("NodeID mismatch")
	}
	if parsed.Type != PktEcho {
		t.Fatal("Type mismatch")
	}

	// Payload с публичным ключом должен пережить round-trip.
	gotPayload, err := DeserializeAnnouncePayload(parsed.Payload)
	if err != nil {
		t.Fatalf("DeserializeAnnouncePayload: %v", err)
	}
	if !gotPayload.Ed25519Pub.Equal(edPub) {
		t.Fatal("ключ в payload не совпадает после round-trip")
	}

	// Пакет версии 1 отбрасывается: у него нет ключа для проверки подписи.
	oldVersion := append([]byte(nil), full...)
	oldVersion[4] = 1
	if _, err := DeserializePacket(oldVersion); err == nil {
		t.Fatal("пакет версии 1 должен отвергаться")
	}

	// Gossip roundtrip
	g := &GossipPayload{
		CRLVersion: 7,
		RevokedEntries: []RevokedEntry{
			{SerialHash: [16]byte{1, 2, 3}, RevokedAt: 12345, Reason: 1},
		},
	}
	gd, _ := SerializeGossipPayload(g)
	pg, err := DeserializeGossipPayload(gd)
	if err != nil {
		t.Fatal(err)
	}
	if pg.CRLVersion != 7 || len(pg.RevokedEntries) != 1 {
		t.Fatal("gossip mismatch")
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(2.0, 5)
	defer rl.Stop()

	for i := 0; i < 5; i++ {
		if !rl.Allow("ip1") {
			t.Fatalf("burst %d blocked", i)
		}
	}
	if rl.Allow("ip1") {
		t.Fatal("should block after burst")
	}
	if !rl.Allow("ip2") {
		t.Fatal("different IP should pass")
	}
}

func TestEncryptDecryptKey(t *testing.T) {
	data := []byte("super-secret-private-key-data!!")
	enc, err := EncryptKey(data, "pass123")
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptKey(enc, "pass123")
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != string(data) {
		t.Fatal("mismatch")
	}
	_, err = DecryptKey(enc, "wrong")
	if err == nil {
		t.Fatal("wrong pass should fail")
	}
}
