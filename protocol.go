package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"time"
)

// Максимальный размер payload в discovery-пакете
const MaxPayloadSize = 512

// DiscoveryPacket — формат UDP-пакета обнаружения.
//
// Структура пакета (все числа big-endian):
//
//	[0:4]   Magic     — 0x4245434E ("BECN"), для отличия от прочего UDP-трафика
//	[4]     Version   — версия протокола (сейчас 2)
//	[5]     Type      — тип пакета (Announce/Echo/Gossip)
//	[6:22]  NodeID    — 16-байтовый идентификатор узла
//	[22:30] Timestamp — Unix-время в секундах (int64, big-endian)
//	[30:62] Nonce     — 32 случайных байта, защита от replay-атак
//	[62:64] PayloadLen— длина payload (uint16, big-endian)
//	[64:64+N] Payload — полезная нагрузка (зависит от типа)
//	[64+N:128+N] Signature — Ed25519-подпись всех предыдущих байтов
//
// Подпись покрывает ВСё до подписи — это гарантирует целостность и подлинность.
// Версия 2: пакеты Announce и Echo обязаны нести AnnouncePayload с публичным
// ключом Ed25519 отправителя. Подпись проверяется этим ключом, а ключ
// сопоставляется с сертификатом узла — так announce привязан к идентичности,
// выданной CA, и чужой узел не может подделать своё присутствие.
type DiscoveryPacket struct {
	Magic     uint32
	Version   uint8
	Type      uint8
	NodeID    [16]byte
	Timestamp int64
	Nonce     [32]byte
	Payload   []byte
}

// PacketHeaderSize — размер заголовка без payload и подписи
const PacketHeaderSize = 64

// SignatureSize — размер Ed25519-подписи
const SignatureSize = 64

// MinPacketSize — минимальный размер валидного пакета (заголовок + пустой payload + подпись)
const MinPacketSize = PacketHeaderSize + SignatureSize // 128

// AnnouncePayloadSize — фиксированный размер payload пакета Announce/Echo.
//
//	[0:32]  Ed25519 public key отправителя
//
// Остаток выделен под будущее расширение, поэтому MaxPayloadSize остаётся
// общей границей.
const AnnouncePayloadSize = 32

// AnnouncePayload — полезная нагрузка пакетов Announce и Echo.
//
// Публичный ключ едет в самом пакете, а не в дополнительном обмене, потому что
// сосед может получить его иначе — только доверившись файлу на диске отправителя.
// С таким payload подпись проверяется сразу, а сам ключ сверяется с сертификатом,
// подписанным нашим CA: расхождение означает подмену.
type AnnouncePayload struct {
	Ed25519Pub ed25519.PublicKey
}

// Serialize кодирует payload в фиксированный 32-байтовый формат.
func (a *AnnouncePayload) Serialize() ([]byte, error) {
	if err := ValidateEd25519Pub(a.Ed25519Pub); err != nil {
		return nil, err
	}
	return append([]byte(nil), a.Ed25519Pub...), nil
}

// DeserializeAnnouncePayload разбирает payload пакета Announce/Echo.
func DeserializeAnnouncePayload(data []byte) (*AnnouncePayload, error) {
	if len(data) != AnnouncePayloadSize {
		return nil, fmt.Errorf("неверный размер announce payload: %d байт (ожидается %d)",
			len(data), AnnouncePayloadSize)
	}
	return &AnnouncePayload{
		Ed25519Pub: ed25519.PublicKey(append([]byte(nil), data...)),
	}, nil
}

// Serialize кодирует DiscoveryPacket в байты (без подписи — подпись добавляется отдельно).
func (p *DiscoveryPacket) Serialize() []byte {
	size := PacketHeaderSize + len(p.Payload)
	buf := make([]byte, size)

	binary.BigEndian.PutUint32(buf[0:4], DiscoveryMagic)
	buf[4] = p.Version
	buf[5] = p.Type
	copy(buf[6:22], p.NodeID[:])
	binary.BigEndian.PutUint64(buf[22:30], uint64(p.Timestamp))
	copy(buf[30:62], p.Nonce[:])
	binary.BigEndian.PutUint16(buf[62:64], uint16(len(p.Payload)))
	copy(buf[64:], p.Payload)

	return buf
}

// DeserializePacket декодирует байты в DiscoveryPacket.
// Возвращает ошибку при любом нарушении формата — это защита от malformed-пакетов.
func DeserializePacket(data []byte) (*DiscoveryPacket, error) {
	if len(data) < MinPacketSize {
		return nil, fmt.Errorf("пакет слишком короток: %d байт (минимум %d)", len(data), MinPacketSize)
	}

	magic := binary.BigEndian.Uint32(data[0:4])
	if magic != DiscoveryMagic {
		return nil, fmt.Errorf("неверный magic: 0x%08X (ожидается 0x%08X)", magic, DiscoveryMagic)
	}

	version := data[4]
	if version != ProtocolVersion {
		// Строгое равенство, а не «не больше»: пакеты v1 не несут
		// публичного ключа Ed25519, поэтому подпись таких пакетов проверить
		// нечем и принять их нельзя.
		return nil, fmt.Errorf("неподдерживаемая версия протокола: %d (ожидается %d)", version, ProtocolVersion)
	}

	pktType := data[5]
	if pktType < PktAnnounce || pktType > PktCertShare {
		return nil, fmt.Errorf("неизвестный тип пакета: %d", pktType)
	}

	var nodeID [16]byte
	copy(nodeID[:], data[6:22])

	timestamp := int64(binary.BigEndian.Uint64(data[22:30]))

	var nonce [32]byte
	copy(nonce[:], data[30:62])

	payloadLen := binary.BigEndian.Uint16(data[62:64])

	// Проверяем, что payloadLen не выходит за границы пакета
	if int(payloadLen) > len(data)-PacketHeaderSize-SignatureSize {
		return nil, fmt.Errorf("payloadLen (%d) превышает доступные данные", payloadLen)
	}

	// Проверяем timestamp: пакеты старше 5 минут отбрасываются
	// Это защищает от replay-атак без необходимости хранить состояние
	now := time.Now().Unix()
	if now-timestamp > 300 || timestamp-now > 60 {
		return nil, fmt.Errorf("timestamp пакета вне допустимого диапазона (разница %d сек)", now-timestamp)
	}

	payload := make([]byte, payloadLen)
	copy(payload, data[PacketHeaderSize:PacketHeaderSize+int(payloadLen)])

	return &DiscoveryPacket{
		Magic:     magic,
		Version:   version,
		Type:      pktType,
		NodeID:    nodeID,
		Timestamp: timestamp,
		Nonce:     nonce,
		Payload:   payload,
	}, nil
}

// DataToSign возвращает байты, которые должны быть подписаны/проверены.
// Это всё до области подписи.
func (p *DiscoveryPacket) DataToSign() []byte {
	return p.Serialize()
}

// GossipPayload — полезная нагрузка для PktGossip-пакетов.
// Содержит обновления CRL (список отозванных сертификатов).
type GossipPayload struct {
	// Number — номер CRL отправителя (CRLNumber из x509.RevocationList).
	// Монотонный и переживает перезапуск, в отличие от прежнего счётчика
	// в памяти, который обнулялся при каждом запуске процесса.
	Number uint64

	// RevokedEntries — отозванные сертификаты, по серийному номеру.
	RevokedEntries []revokedCert
}

// maxGossipEntries ограничивает число отзывов в одном gossip-пакете.
const maxGossipEntries = 1000

// gossipMaxSerialLen — максимальная длина серийника в десятичной записи.
// Серийники выпускаются 128-битными, но 39 символов дают запас.
const gossipMaxSerialLen = 39

// SerializeGossipPayload кодирует gossip-нагрузку в байты.
//
//	[8 байт Number]
//	[запись: serialLen(1) serial(serialLen) revokedAt(8) reason(1)]*
//
// Серийник кодируется текстом десятичной записи: это читаемо при дампе пакета
// и не зависит от длины big.Int, как было бы при побайтовом кодировании.
func SerializeGossipPayload(g *GossipPayload) ([]byte, error) {
	if len(g.RevokedEntries) > maxGossipEntries {
		return nil, fmt.Errorf("слишком много записей в CRL gossip: %d (макс %d)",
			len(g.RevokedEntries), maxGossipEntries)
	}

	buf := make([]byte, 8, 8+len(g.RevokedEntries)*(gossipMaxSerialLen+10))
	binary.BigEndian.PutUint64(buf, g.Number)

	for _, entry := range g.RevokedEntries {
		if entry.SerialNumber == nil {
			continue
		}

		serial := []byte(entry.SerialNumber.String())
		if len(serial) > gossipMaxSerialLen {
			return nil, fmt.Errorf("слишком длинный серийник для gossip: %d байт", len(serial))
		}

		buf = append(buf, uint8(len(serial)))
		buf = append(buf, serial...)

		var timeBuf [8]byte
		binary.BigEndian.PutUint64(timeBuf[:], uint64(entry.RevokedAt.Unix()))
		buf = append(buf, timeBuf[:]...)
		buf = append(buf, entry.Reason)
	}

	return buf, nil
}

// DeserializeGossipPayload разбирает gossip-нагрузку из байтов.
func DeserializeGossipPayload(data []byte) (*GossipPayload, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("gossip payload слишком короткий")
	}

	number := binary.BigEndian.Uint64(data[:8])

	rest := data[8:]
	entries := make([]revokedCert, 0, 16)

	for len(rest) > 0 {
		if len(rest) < 1+8+1 {
			return nil, fmt.Errorf("обрыв записи в gossip payload")
		}

		serialLen := int(rest[0])
		rest = rest[1:]

		if serialLen == 0 || serialLen > gossipMaxSerialLen {
			return nil, fmt.Errorf("некорректная длина серийника в gossip: %d", serialLen)
		}
		if len(rest) < serialLen+8+1 {
			return nil, fmt.Errorf("обрыв записи в gossip payload")
		}

		serial := new(big.Int)
		if _, ok := serial.SetString(string(rest[:serialLen]), 10); !ok {
			return nil, fmt.Errorf("некорректный серийник в gossip payload")
		}
		rest = rest[serialLen:]

		revokedAt := int64(binary.BigEndian.Uint64(rest[:8]))
		reason := rest[8]
		rest = rest[9:]

		entries = append(entries, revokedCert{
			SerialNumber: serial,
			RevokedAt:    time.Unix(revokedAt, 0),
			Reason:       reason,
		})
	}

	return &GossipPayload{
		Number:         number,
		RevokedEntries: entries,
	}, nil
}

// IsBroadcastAddr проверяет, является ли адрес broadcast-адресом.
func IsBroadcastAddr(addr *net.UDPAddr) bool {
	ip := addr.IP.To4()
	if ip == nil {
		ip = addr.IP.To16()
	}
	if ip == nil {
		return false
	}
	// Все байты 0xFF — классический broadcast
	for _, b := range ip {
		if b != 0xFF {
			return false
		}
	}
	return true
}
