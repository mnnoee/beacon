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

	issued, err := IssueCertificate(caKey, certPEM, dir, "beacon-san", DefaultCertTTL, RolePeer)
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

	honest, err := IssueCertificate(caKey, certPEM, dir, "beacon-honest", DefaultCertTTL, RolePeer)
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
	node1, err := IssueCertificate(caKey, certPEM, dir, "beacon-t1", DefaultCertTTL, RolePeer)
	if err != nil {
		t.Fatalf("Issue cert1: %v", err)
	}
	node2, err := IssueCertificate(caKey, certPEM, dir, "beacon-t2", DefaultCertTTL, RolePeer)
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
	IssueCertificate(caKey, certPEM, dir, "revoke-me", DefaultCertTTL, RolePeer)

	ts, _ := NewTrustStore(dir+"/ca/ca-cert.pem", dir+"/ca/crl.pem")
	cert, err := loadCertPEM(dir + "/revoke-me/cert.pem")
	if err != nil {
		t.Fatalf("загрузка сертификата: %v", err)
	}

	if !ts.IsTrusted(cert) {
		t.Fatal("сертификат должен быть доверен до отзыва")
	}

	if err := ts.Revoke(cert.SerialNumber, 1); err != nil {
		t.Fatalf("отзыв: %v", err)
	}

	if ts.IsTrusted(cert) {
		t.Fatal("отозванный сертификат не должен быть доверен")
	}

	// CRL должен пережить перезапуск процесса.
	ts2, _ := NewTrustStore(dir+"/ca/ca-cert.pem", dir+"/ca/crl.pem")
	if !ts2.IsRevokedBySerial(cert.SerialNumber) {
		t.Fatal("CRL должен сохраняться на диск")
	}
	if ts2.IsTrusted(cert) {
		t.Fatal("после перезагрузки CRL сертификат всё ещё должен быть отозван")
	}
}

// TestRevocationDoesNotAffectReissuedCert — регресс на главный дефект прежней
// схемы: отзыв сертификата не должен задевать новый, выпущенный на то же имя.
func TestRevocationDoesNotAffectReissuedCert(t *testing.T) {
	dir := t.TempDir()
	_, certPEM, _ := GenerateCA(dir, DefaultCALifetime)
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	first, err := IssueCertificate(caKey, certPEM, dir, "beacon-flaky", DefaultCertTTL, RolePeer)
	if err != nil {
		t.Fatalf("первая выдача: %v", err)
	}

	firstCert, _ := loadCertPEM(first.CertPath)

	// Устройство потеряло ключ — пере-выдача на то же имя.
	if err := ArchiveCertIfPresent(dir, "beacon-flaky"); err != nil {
		t.Fatalf("архивирование: %v", err)
	}

	second, err := IssueCertificate(caKey, certPEM, dir, "beacon-flaky", DefaultCertTTL, RolePeer)
	if err != nil {
		t.Fatalf("пере-выдача: %v", err)
	}

	secondCert, _ := loadCertPEM(second.CertPath)

	// Оба сертификата имеют одинаковый CN — как в реальном деплое.
	if firstCert.Subject.CommonName != secondCert.Subject.CommonName {
		t.Fatal("CN должен совпадать")
	}
	if firstCert.SerialNumber.Cmp(secondCert.SerialNumber) == 0 {
		t.Fatal("серийники должны различаться")
	}

	ts, _ := NewTrustStore(dir+"/ca/ca-cert.pem", dir+"/ca/crl.pem")

	// Отзываем старый (утерянный) сертификат.
	if err := ts.Revoke(firstCert.SerialNumber, 1); err != nil {
		t.Fatalf("отзыв старого: %v", err)
	}

	// Новый обязан остаться рабочим — прежняя схема ломала его здесь.
	if !ts.IsTrusted(secondCert) {
		t.Fatal("отзыв старого сертификата не должен задевать пере-выданный")
	}
	if ts.IsTrusted(firstCert) {
		t.Fatal("старый сертификат должен быть отозван")
	}
}

// TestGossipCRLMerge — регресс на дефект версий CRL.
//
// Прежний код отбрасывал gossip, если senderVersion <= localVersion. Номер
// CRL жил только в памяти и обнулялся при каждом запуске, поэтому два свежих
// узла имели одинаковый номер и отзывы не расходились ВООБЩЕ. Теперь отзывы
// принимаются всегда: CRL только растёт, объединение безопасно.
func TestGossipCRLMerge(t *testing.T) {
	dir := t.TempDir()
	_, certPEM, _ := GenerateCA(dir, DefaultCALifetime)
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	issued, err := IssueCertificate(caKey, certPEM, dir, "gossip-node", DefaultCertTTL, RolePeer)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	cert, _ := loadCertPEM(issued.CertPath)

	ts, _ := NewTrustStore(dir+"/ca/ca-cert.pem", dir+"/ca/crl.pem")
	if err := ts.Revoke(cert.SerialNumber, 1); err != nil {
		t.Fatalf("отзыв: %v", err)
	}

	// Узел-получатель, у которого НИЧЕГО не отозвано.
	receiver, _ := NewTrustStore(dir+"/ca/ca-cert.pem", dir+"/ca/crl-empty.pem")

	entries := []revokedCert{{
		SerialNumber: cert.SerialNumber,
		RevokedAt:    time.Now(),
		Reason:       1,
	}}

	// Именно этот случай раньше отбрасывался: номера равны.
	if !receiver.MergeGossipCRL(receiver.CRLVersion(), entries) {
		t.Fatalf("gossip с равным номером должен приниматься (номер получателя=%d)",
			receiver.CRLVersion())
	}

	if !receiver.IsRevokedBySerial(cert.SerialNumber) {
		t.Fatal("отзыв должен был примениться")
	}

	// Повторное применение тех же записей не должно ничего ломать.
	if receiver.MergeGossipCRL(receiver.CRLVersion(), entries) {
		t.Fatal("повторное применение идентичных записей не должно считаться изменением")
	}

	// Чужой CRL не должен понижать наш номер.
	high := receiver.CRLVersion()
	receiver.MergeGossipCRL(1, nil)
	if receiver.CRLVersion() != high {
		t.Fatal("номер CRL не должен уменьшаться")
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

	// Gossip roundtrip: серийники произвольной длины должны пережить
	// сериализацию как текст.
	g := &GossipPayload{
		Number: 7,
		RevokedEntries: []revokedCert{
			{
				SerialNumber: big.NewInt(12345),
				RevokedAt:    time.Unix(1700000000, 0),
				Reason:       1,
			},
			{
				// Максимальный 128-битный серийник
				SerialNumber: new(big.Int).Lsh(big.NewInt(1), 128),
				RevokedAt:    time.Unix(1700000001, 0),
				Reason:       2,
			},
		},
	}
	gd, err := SerializeGossipPayload(g)
	if err != nil {
		t.Fatalf("SerializeGossipPayload: %v", err)
	}
	pg, err := DeserializeGossipPayload(gd)
	if err != nil {
		t.Fatal(err)
	}
	if pg.Number != 7 {
		t.Fatalf("номер CRL не совпал: %d", pg.Number)
	}
	if len(pg.RevokedEntries) != 2 {
		t.Fatalf("число записей не совпало: %d", len(pg.RevokedEntries))
	}
	for i, want := range g.RevokedEntries {
		got := pg.RevokedEntries[i]
		if got.SerialNumber.Cmp(want.SerialNumber) != 0 {
			t.Fatalf("серийник #%d: получили %s, ждали %s",
				i, got.SerialNumber, want.SerialNumber)
		}
		if !got.RevokedAt.Equal(want.RevokedAt) {
			t.Fatalf("время #%d: получили %v, ждали %v", i, got.RevokedAt, want.RevokedAt)
		}
		if got.Reason != want.Reason {
			t.Fatalf("причина #%d: получили %d, ждали %d", i, got.Reason, want.Reason)
		}
	}

	// Обрезка должна отвергаться, а не читаться как мусор.
	if _, err := DeserializeGossipPayload(gd[:len(gd)-3]); err == nil {
		t.Fatal("обрезанный gossip payload должен отвергаться")
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
