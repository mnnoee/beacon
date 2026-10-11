package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
	"time"
)

// setupGossipTest готовит два узла с общим CA и взаимно доверенными
// сертификатами — минимальное состояние, при котором gossip вообще может
// дойти до адресата.
func setupGossipTest(t *testing.T) (sender, receiver *BeaconNode) {
	t.Helper()

	dir := t.TempDir()

	_, caCertPEM, err := GenerateCA(dir, DefaultCALifetime)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	caKey, err := LoadCAKey(dir + "/ca/ca-key.pem")
	if err != nil {
		t.Fatalf("LoadCAKey: %v", err)
	}

	issue := func(cn string) *IssuedNode {
		issued, err := IssueCertificate(caKey, caCertPEM, dir, cn, DefaultCertTTL, RolePeer)
		if err != nil {
			t.Fatalf("IssueCertificate(%s): %v", cn, err)
		}
		return issued
	}

	// Оба узла должны быть выданы: BeaconNode требует существующий
	// ed25519-key.pem, соответствующий сертификату.
	issue("beacon-first")
	issue("beacon-second")

	cfgA := DefaultConfig()
	cfgA.DataDir = dir
	cfgA.NodeName = "beacon-first"

	nodeA, err := NewBeaconNode(cfgA)
	if err != nil {
		t.Fatalf("NewBeaconNode(A): %v", err)
	}
	cfgB := DefaultConfig()
	cfgB.DataDir = dir
	cfgB.NodeName = "beacon-second"

	nodeB, err := NewBeaconNode(cfgB)
	if err != nil {
		t.Fatalf("NewBeaconNode(B): %v", err)
	}

	// Получатель доверяет сертификату отправителя: без этого mTLS-соединение
	// не установилось бы, и gossip был бы невозможен в принципе.
	return nodeA, nodeB
}

// TestGossipSignatureRequired — пакет gossip без корректной подписи отклоняется.
func TestGossipSignatureRequired(t *testing.T) {
	sender, receiver := setupGossipTest(t)

	// Отправитель отзывает сертификат, чтобы было что рассылать.
	caKey, err := LoadCAKey(sender.config.DataDir + "/ca/ca-key.pem")
	if err != nil {
		t.Fatalf("загрузка ключа CA: %v", err)
	}
	caCertPEM, err := os.ReadFile(sender.config.DataDir + "/ca/ca-cert.pem")
	if err != nil {
		t.Fatalf("чтение сертификата CA: %v", err)
	}

	victim, err := IssueCertificate(caKey, caCertPEM, sender.config.DataDir,
		"beacon-victim", DefaultCertTTL, RolePeer)
	if err != nil {
		t.Fatalf("выдача сертификата жертвы: %v", err)
	}

	victimCert, err := loadCertPEM(victim.CertPath)
	if err != nil {
		t.Fatalf("загрузка сертификата: %v", err)
	}

	if err := sender.trustStore.Revoke(victimCert.SerialNumber, 1); err != nil {
		t.Fatalf("отзыв: %v", err)
	}

	entries := sender.trustStore.GetRevokedEntries()
	if len(entries) == 0 {
		t.Fatal("у отправителя должен быть хотя бы один отзыв")
	}

	payload, err := SerializeGossipPayload(&GossipPayload{
		Number:         sender.trustStore.CRLVersion(),
		RevokedEntries: entries,
	})
	if err != nil {
		t.Fatalf("SerializeGossipPayload: %v", err)
	}

	build := func(priv ed25519.PrivateKey, nodeID [16]byte) []byte {
		pkt := &DiscoveryPacket{
			Magic:     DiscoveryMagic,
			Version:   ProtocolVersion,
			Type:      PktGossip,
			NodeID:    nodeID,
			Timestamp: time.Now().Unix(),
			Payload:   payload,
		}
		rand.Read(pkt.Nonce[:])
		return SignPacket(pkt, priv)
	}

	peer := &DiscoveredPeer{NodeID: sender.nodeID}

	t.Run("корректная подпись принимается", func(t *testing.T) {
		full := build(sender.edPriv, sender.nodeID)

		if err := receiver.verifyGossipSignature(&DiscoveryPacket{NodeID: sender.nodeID},
			peer, full); err != nil {
			t.Fatalf("корректно подписанный gossip должен приниматься: %v", err)
		}
	})

	t.Run("испорченная подпись отклоняется", func(t *testing.T) {
		full := build(sender.edPriv, sender.nodeID)
		full[len(full)-1] ^= 0xFF

		err := receiver.verifyGossipSignature(&DiscoveryPacket{NodeID: sender.nodeID}, peer, full)
		if err == nil {
			t.Fatal("пакет с испорченной подписью должен отклоняться")
		}
	})

	t.Run("подпись чужим ключом отклоняется", func(t *testing.T) {
		_, roguePriv, _ := ed25519.GenerateKey(rand.Reader)

		// NodeID остаётся настоящим — проверка подписи всё равно должна
		// отклонить пакет, потому что приватный ключ чужой.
		full := build(roguePriv, sender.nodeID)

		err := receiver.verifyGossipSignature(&DiscoveryPacket{NodeID: sender.nodeID}, peer, full)
		if err == nil {
			t.Fatal("пакет, подписанный чужим ключом, должен отклоняться")
		}
	})

	t.Run("чужой NodeID отклоняется", func(t *testing.T) {
		// Пакет подписан настоящим ключом, но объявляет себя другим узлом.
		other := [16]byte{0xAA, 0xBB, 0xCC}
		full := build(sender.edPriv, other)

		err := receiver.verifyGossipSignature(&DiscoveryPacket{NodeID: other}, peer, full)
		if err == nil {
			t.Fatal("gossip от чужого NodeID должен отклоняться")
		}
	})
}

// TestRegisterPeerSigningKeyRejectsMismatch — узел не может зарегистрировать
// ключ, не соответствующий своему NodeID.
func TestRegisterPeerSigningKeyRejectsMismatch(t *testing.T) {
	sender, receiver := setupGossipTest(t)

	cert, err := loadCertPEM(sender.config.DataDir + "/beacon-first/cert.pem")
	if err != nil {
		t.Fatalf("загрузка сертификата отправителя: %v", err)
	}

	wrongID := [16]byte{1, 2, 3, 4}
	receiver.registerPeerSigningKey(wrongID, cert)

	// Ключ не должен был зарегистрироваться под чужим ID.
	if _, err := receiver.trustStore.SigningKey(wrongID); err == nil {
		t.Fatal("ключ с несовпадающим NodeID не должен регистрироваться")
	}

	// А с настоящим ID — должен.
	receiver.registerPeerSigningKey(sender.nodeID, cert)
	if _, err := receiver.trustStore.SigningKey(sender.nodeID); err != nil {
		t.Fatalf("с корректным NodeID ключ должен регистрироваться: %v", err)
	}
}
