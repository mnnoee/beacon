package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

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
	node1ID := GenerateNodeID()
	node2ID := GenerateNodeID()
	_, _, err = IssueCertificate(caKey, certPEM, dir, "beacon-t1", node1ID, DefaultCertTTL)
	if err != nil {
		t.Fatalf("Issue cert1: %v", err)
	}
	_, _, err = IssueCertificate(caKey, certPEM, dir, "beacon-t2", node2ID, DefaultCertTTL)
	if err != nil {
		t.Fatalf("Issue cert2: %v", err)
	}

	// Загрузка CA pool
	caPEM, _ := os.ReadFile(dir + "/ca/ca-cert.pem")
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	// Загрузка ключей
	srvCert, _ := tls.LoadX509KeyPair(dir+"/beacon-t1/cert.pem", dir+"/beacon-t1/key.pem")
	cliCert, _ := tls.LoadX509KeyPair(dir+"/beacon-t2/cert.pem", dir+"/beacon-t2/key.pem")

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
		cn string
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
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5*time.Second}, "tcp", ln.Addr().String(), cliCfg)
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
	nodeID := GenerateNodeID()
	IssueCertificate(caKey, certPEM, dir, "revoke-me", nodeID, DefaultCertTTL)

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
	nodeID := GenerateNodeID()
	IssueCertificate(caKey, certPEM, dir, "gossip-node", nodeID, DefaultCertTTL)
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
	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktEcho,
		NodeID:    GenerateNodeID(),
		Timestamp: time.Now().Unix(),
	}
	rand.Read(pkt.Nonce[:])

	data := pkt.Serialize()
	// Serialize() produces header only (64 bytes); full packet = header + sig = 128
	if len(data) != PacketHeaderSize {
		t.Fatalf("header size: got %d want %d", len(data), PacketHeaderSize)
	}

	// DeserializePacket expects full packet (header + sig). Pad with zero sig for format check.
	fullData := make([]byte, PacketHeaderSize+SignatureSize)
	copy(fullData, data)
	parsed, err := DeserializePacket(fullData)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.NodeID != pkt.NodeID {
		t.Fatal("NodeID mismatch")
	}
	if parsed.Type != PktEcho {
		t.Fatal("Type mismatch")
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
