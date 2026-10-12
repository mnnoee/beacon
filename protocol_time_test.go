package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

// signedAnnounce собирает подписанный announce с произвольным временем в пакете.
func signedAnnounce(t *testing.T, priv ed25519.PrivateKey, ts time.Time) []byte {
	t.Helper()

	payload, err := (&AnnouncePayload{Ed25519Pub: priv.Public().(ed25519.PublicKey)}).Serialize()
	if err != nil {
		t.Fatalf("payload: %v", err)
	}

	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktAnnounce,
		NodeID:    NodeIDFromEd25519Pub(priv.Public().(ed25519.PublicKey)),
		Timestamp: ts.Unix(),
		Payload:   payload,
	}

	return SignPacket(pkt, priv)
}

// TestPacketTimeWindowIsSymmetric — окно времени симметрично.
//
// Прежняя проверка принимала пакет «из прошлого» в пределах 5 минут, но
// «из будущего» — только 60 секунд, причём числа были продублированы в двух
// местах. Узел с часами, ушедшими вперёд на несколько минут, не мог
// объявиться: его пакеты отбрасывались по timestamp, а не по подписи.
func TestPacketTimeWindowIsSymmetric(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("генерация ключа: %v", err)
	}

	cases := []struct {
		name  string
		shift time.Duration
		ok    bool
	}{
		{"сейчас", 0, true},
		{"минуту назад", -time.Minute, true},
		{"две минуты вперёд", 2 * time.Minute, true},
		{"четыре минуты вперёд", 4 * time.Minute, true},
		{"шесть минут назад", -6 * time.Minute, false},
		{"шесть минут вперёд", 6 * time.Minute, false},
		{"час назад", -time.Hour, false},
	}

	for _, tc := range cases {
		packet := signedAnnounce(t, priv, time.Now().Add(tc.shift))

		_, err := DeserializePacket(packet)

		if tc.ok && err != nil {
			t.Fatalf("%s: пакет должен приниматься: %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%s: пакет должен отбрасываться", tc.name)
		}
	}
}

// TestDiscoveryRejectsPacketOutsideWindow — обработчик не доходит до пиров:
// проверка времени живёт в десериализаторе, второй копии в обработчике нет.
func TestDiscoveryRejectsPacketOutsideWindow(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("генерация ключа: %v", err)
	}

	seen := false
	d := NewDiscovery([16]byte{}, priv, 1, "127.255.255.255", "127.0.0.1", NewRateLimiter(1000, 100))
	d.OnDiscover(func(_ [16]byte, _ *net.UDPAddr, _ uint8) { seen = true })

	d.handlePacket(signedAnnounce(t, priv, time.Now().Add(-time.Hour)), mustUDPAddr("127.0.0.1:1984"))

	if seen {
		t.Fatal("пакет вне окна времени не должен доходить до обработчика пиров")
	}
}

// TestDiscoveryAcceptsClockAhead — узел с часами на четыре минуты вперёд не
// отбрасывается. Именно этот случай ломал сеть при асимметричном окне.
func TestDiscoveryAcceptsClockAhead(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("генерация ключа: %v", err)
	}

	// У discovery свой ключ: пакет с тем же NodeID обработчик счёл бы своим.
	_, ownPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("генерация ключа discovery: %v", err)
	}
	ownNodeID := NodeIDFromEd25519Pub(ownPriv.Public().(ed25519.PublicKey))

	port := freeUDPPort(t)
	d := NewDiscovery(ownNodeID, ownPriv, port, "127.255.255.255", "127.0.0.1", NewRateLimiter(1000, 100))

	seen := false
	d.OnDiscover(func(_ [16]byte, _ *net.UDPAddr, _ uint8) { seen = true })

	if err := d.Start(); err != nil {
		t.Fatalf("запуск discovery: %v", err)
	}
	t.Cleanup(d.Stop)

	d.handlePacket(signedAnnounce(t, priv, time.Now().Add(4*time.Minute)), mustUDPAddr("127.0.0.1:1984"))

	if !seen {
		t.Fatal("узел с часами впереди должен обнаруживаться")
	}
}
