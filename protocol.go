package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
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
	if pktType < PktAnnounce || pktType > PktGossip {
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
	// Версия CRL отправителя (счетчик, увеличивается при каждом отзыве)
	CRLVersion uint32

	// Список отозванных серийных номеров (каждый 16 байт — SHA-256 от DN)
	RevokedEntries []RevokedEntry
}

// RevokedEntry — одна запись об отозванном сертификате.
type RevokedEntry struct {
	// Серийный номер сертификата (SHA-256 от distinguished name, 16 байт)
	SerialHash [16]byte

	// Время отзыва (Unix seconds)
	RevokedAt int64

	// Причина отзыва (0 — не определена, 1 — компрометация ключа, 2 — выход из сети)
	Reason uint8
}

// SerializeGossipPayload кодирует gossip-нагрузку в байты.
func SerializeGossipPayload(g *GossipPayload) ([]byte, error) {
	if len(g.RevokedEntries) > 1000 {
		return nil, fmt.Errorf("слишком много записей в CRL gossip: %d (макс 1000)", len(g.RevokedEntries))
	}

	size := 4 + len(g.RevokedEntries)*25 // 4(версия) + N*(16+8+1)
	buf := make([]byte, size)

	binary.BigEndian.PutUint32(buf[0:4], g.CRLVersion)

	offset := 4
	for _, entry := range g.RevokedEntries {
		copy(buf[offset:offset+16], entry.SerialHash[:])
		binary.BigEndian.PutUint64(buf[offset+16:offset+24], uint64(entry.RevokedAt))
		buf[offset+24] = entry.Reason
		offset += 25
	}

	return buf, nil
}

// DeserializeGossipPayload декодирует gossip-нагрузку.
func DeserializeGossipPayload(data []byte) (*GossipPayload, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("gossip payload слишком короток")
	}

	crlVersion := binary.BigEndian.Uint32(data[0:4])
	remaining := data[4:]

	if len(remaining)%25 != 0 {
		return nil, fmt.Errorf("неверная длина gossip payload: %d (должно быть кратно 25)", len(remaining))
	}

	count := len(remaining) / 25
	entries := make([]RevokedEntry, count)

	for i := 0; i < count; i++ {
		base := i * 25
		var entry RevokedEntry
		copy(entry.SerialHash[:], remaining[base:base+16])
		entry.RevokedAt = int64(binary.BigEndian.Uint64(remaining[base+16 : base+24]))
		entry.Reason = remaining[base+24]
		entries[i] = entry
	}

	return &GossipPayload{
		CRLVersion:     crlVersion,
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
