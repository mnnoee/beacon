package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
)

// SO_REUSEPORT — Linux-специфичная опция сокета (значение 15).
// Позволяет нескольким процессам слушать один UDP-порт.
// Определена вручную, т.к. syscall/stdlib не экспортирует её.
const SO_REUSEPORT = 15

// Discovery — модуль сетевого обнаружения маячков через UDP broadcast.
//
// Протокол:
// 1. Каждый маячок периодически отправляет PktAnnounce в broadcast
// 2. Получив Announce от неизвестного узла, отправляем PktEcho
// 3. Получив Echo, инициируем TLS-соединение для верификации
//
// Защита:
// - Все пакеты подписываются Ed25519-ключом узла
// - Nonce + timestamp предотвращают replay-атаки
// - Rate limiter защищает от UDP-флуда
// - Payload не содержит секретов — обнаружение публично

// DiscoveryCallback вызывается при обнаружении нового пира.
type DiscoveryCallback func(senderID [16]byte, addr *net.UDPAddr, pktType uint8)

// Discovery управляет UDP-обнаружением пиров в локальной сети.
type Discovery struct {
	mu sync.Mutex

	nodeID    [16]byte
	privKey   ed25519.PrivateKey
	pubKey    ed25519.PublicKey

	port        int
	broadcastIP string
	bindAddr    string

	conn     *net.UDPConn
	limiter  *RateLimiter
	callback DiscoveryCallback
	stopCh   chan struct{}
	wg       sync.WaitGroup

	// Кэш отправленных/виденных пакетов (replay protection + игнор broadcast)
	sentNonces map[[32]byte]time.Time
}

// NewDiscovery создаёт новый экземпляр модуля обнаружения.
func NewDiscovery(nodeID [16]byte, privKey ed25519.PrivateKey, port int, broadcastIP, bindAddr string, limiter *RateLimiter) *Discovery {
	return &Discovery{
		nodeID:     nodeID,
		privKey:    privKey,
		pubKey:     privKey.Public().(ed25519.PublicKey),
		port:       port,
		broadcastIP: broadcastIP,
		bindAddr:   bindAddr,
		limiter:    limiter,
		stopCh:     make(chan struct{}),
		sentNonces: make(map[[32]byte]time.Time),
	}
}

// OnDiscover устанавливает callback для обработки обнаруженных пиров.
func (d *Discovery) OnDiscover(cb DiscoveryCallback) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.callback = cb
}

// Start запускает discovery-модуль.
func (d *Discovery) Start() error {
	addr := &net.UDPAddr{
		IP:   net.ParseIP(d.bindAddr),
		Port: d.port,
	}

	// Используем SO_REUSEPORT для возможности запуска нескольких
	// экземпляров маячка на одной машине (для тестирования).
	// В продакшене каждый маячок — отдельная машина, но SO_REUSEPORT
	// не вредит и упрощает разработку/тестирование.
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
			})
		},
	}

	listener, err := lc.ListenPacket(context.Background(), "udp4", addr.String())
	if err != nil {
		return fmt.Errorf("привязка к UDP %s:%d: %w", d.bindAddr, d.port, err)
	}

	conn := listener.(*net.UDPConn)

	if err := conn.SetReadBuffer(1024 * 1024); err != nil {
		log.Printf("[Discovery] предупреждение: не удалось увеличить read buffer: %v", err)
	}

	d.conn = conn

	d.wg.Add(1)
	go d.receiveLoop()

	d.wg.Add(1)
	go d.broadcastLoop()

	log.Printf("[Discovery] запущен на %s:%d (broadcast: %s)", d.bindAddr, d.port, d.broadcastIP)
	return nil
}

// Stop останавливает discovery-модуль.
func (d *Discovery) Stop() {
	close(d.stopCh)
	if d.conn != nil {
		d.conn.Close()
	}
	d.wg.Wait()
	log.Println("[Discovery] остановлен")
}

// broadcastLoop периодически отправляет PktAnnounce в сеть.
func (d *Discovery) broadcastLoop() {
	defer d.wg.Done()

	time.Sleep(1 * time.Second)

	ticker := time.NewTicker(DefaultBroadcastInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			if err := d.sendAnnounce(); err != nil {
				log.Printf("[Discovery] ошибка отправки announce: %v", err)
			}
		}
	}
}

// sendAnnounce создаёт и отправляет PktAnnounce.
func (d *Discovery) sendAnnounce() error {
	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktAnnounce,
		NodeID:    d.nodeID,
		Timestamp: time.Now().Unix(),
	}

	if _, err := rand.Read(pkt.Nonce[:]); err != nil {
		return fmt.Errorf("генерация nonce: %w", err)
	}

	dataToSign := pkt.Serialize()
	pktSig := ed25519.Sign(d.privKey, dataToSign)
	fullPacket := append(dataToSign, pktSig...)

	destAddr := &net.UDPAddr{
		IP:   net.ParseIP(d.broadcastIP),
		Port: d.port,
	}

	_, err := d.conn.WriteToUDP(fullPacket, destAddr)
	if err != nil {
		return fmt.Errorf("отправка broadcast: %w", err)
	}

	d.mu.Lock()
	d.sentNonces[pkt.Nonce] = time.Now()
	for nonce, t := range d.sentNonces {
		if time.Since(t) > 30*time.Second {
			delete(d.sentNonces, nonce)
		}
	}
	d.mu.Unlock()

	return nil
}

// receiveLoop читает UDP-пакеты и обрабатывает их.
func (d *Discovery) receiveLoop() {
	defer d.wg.Done()

	buf := make([]byte, MaxPacketSize)

	for {
		select {
		case <-d.stopCh:
			return
		default:
		}

		if err := d.conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return
		}

		numBytes, remoteAddr, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("[Discovery] ошибка чтения: %v", err)
			continue
		}

		if numBytes < MinPacketSize {
			continue
		}

		d.handlePacket(buf[:numBytes], remoteAddr)
	}
}

// handlePacket обрабатывает входящий UDP-пакет.
func (d *Discovery) handlePacket(data []byte, remoteAddr *net.UDPAddr) {
	if d.limiter != nil && !d.limiter.Allow(remoteAddr.IP.String()) {
		log.Printf("[Discovery] rate limit: пакет от %s отброшен", remoteAddr.IP)
		return
	}

	pkt, err := DeserializePacket(data)
	if err != nil {
		log.Printf("[Discovery] невалидный пакет от %s: %v", remoteAddr, err)
		return
	}

	if pkt.NodeID == d.nodeID {
		return
	}

	if d.isNonceSeen(pkt.Nonce) {
		return
	}

	d.mu.Lock()
	cb := d.callback
	d.mu.Unlock()

	if cb != nil {
		cb(pkt.NodeID, remoteAddr, pkt.Type)
	}

	if pkt.Type == PktAnnounce {
		d.sendEcho(pkt.NodeID, remoteAddr)
	}
}

// sendEcho отправляет PktEcho в ответ на Announce.
func (d *Discovery) sendEcho(targetID [16]byte, targetAddr *net.UDPAddr) {
	_ = targetID

	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktEcho,
		NodeID:    d.nodeID,
		Timestamp: time.Now().Unix(),
	}

	if _, err := rand.Read(pkt.Nonce[:]); err != nil {
		log.Printf("[Discovery] генерация nonce для echo: %v", err)
		return
	}

	dataToSign := pkt.Serialize()
	pktSig := ed25519.Sign(d.privKey, dataToSign)
	fullPacket := append(dataToSign, pktSig...)

	_, err := d.conn.WriteToUDP(fullPacket, targetAddr)
	if err != nil {
		log.Printf("[Discovery] отправка echo: %v", err)
	}
}

// isNonceSeen проверяет, был ли nonce уже обработан (replay protection).
func (d *Discovery) isNonceSeen(nonce [32]byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	seen, exists := d.sentNonces[nonce]
	if exists && time.Since(seen) < 300*time.Second {
		return true
	}

	d.sentNonces[nonce] = time.Now()
	return false
}

// SendGossip отправляет gossip-пакет конкретному узлу (unicast по UDP).
func (d *Discovery) SendGossip(targetAddr *net.UDPAddr, crlVersion uint32, entries []RevokedEntry) error {
	gossipPayload := &GossipPayload{
		CRLVersion:     crlVersion,
		RevokedEntries: entries,
	}

	payload, err := SerializeGossipPayload(gossipPayload)
	if err != nil {
		return fmt.Errorf("сериализация gossip: %w", err)
	}

	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktGossip,
		NodeID:    d.nodeID,
		Timestamp: time.Now().Unix(),
		Payload:   payload,
	}

	if _, err := rand.Read(pkt.Nonce[:]); err != nil {
		return fmt.Errorf("генерация nonce: %w", err)
	}

	dataToSign := pkt.Serialize()
	pktSig := ed25519.Sign(d.privKey, dataToSign)
	fullPacket := append(dataToSign, pktSig...)

	_, err = d.conn.WriteToUDP(fullPacket, targetAddr)
	return err
}
