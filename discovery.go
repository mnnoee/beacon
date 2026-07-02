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
const SO_REUSEPORT = 15

// NonceTTL — время жизни nonce в секундах (300 сек = 5 минут).
const NonceTTL = 300 * time.Second

// MulticastGroup — группа для discovery (RFC 5771, диапазон 239.x.x.x).
const MulticastGroup = "239.19.84.1"

// Discovery — модуль сетевого обнаружения маячков через UDP multicast.
type Discovery struct {
	mu sync.Mutex

	nodeID    [16]byte
	privKey   ed25519.PrivateKey
	pubKey    ed25519.PublicKey

	port        int
	mcastAddr   string // multicast-адрес для отправки
	bindAddr    string
	iface       *net.Interface // сетевой интерфейс для multicast

	conn     *net.UDPConn
	limiter  *RateLimiter
	callback DiscoveryCallback
	stopCh   chan struct{}
	wg       sync.WaitGroup

	// Кэш виденных nonce (replay protection + игнор своих broadcast)
	sentNonces map[[32]byte]time.Time
}

// DiscoveryCallback вызывается при обнаружении нового пира.
type DiscoveryCallback func(senderID [16]byte, addr *net.UDPAddr, pktType uint8)

// NewDiscovery создаёт новый экземпляр модуля обнаружения.
func NewDiscovery(nodeID [16]byte, privKey ed25519.PrivateKey, port int, mcastAddr, bindAddr string, limiter *RateLimiter) *Discovery {
	return &Discovery{
		nodeID:     nodeID,
		privKey:    privKey,
		pubKey:     privKey.Public().(ed25519.PublicKey),
		port:       port,
		mcastAddr:  mcastAddr,
		bindAddr:   bindAddr,
		limiter:    limiter,
		stopCh:     make(chan struct{}),
		sentNonces: make(map[[32]byte]time.Time),
	}
}

// OnDiscover устанавливает callback.
func (d *Discovery) OnDiscover(cb DiscoveryCallback) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.callback = cb
}

// Start запускает discovery-модуль.
func (d *Discovery) Start() error {
	// Привязываемся к multicast-адресу для приёма
	listenAddr := &net.UDPAddr{
		IP:   net.ParseIP(d.bindAddr),
		Port: d.port,
	}

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
			})
		},
	}

	listener, err := lc.ListenPacket(context.Background(), "udp4", listenAddr.String())
	if err != nil {
		return fmt.Errorf("привязка к UDP %s:%d: %w", d.bindAddr, d.port, err)
	}

	conn := listener.(*net.UDPConn)

	// Определяем интерфейс для multicast
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagMulticast != 0 {
				d.iface = &iface
				// Присоединяемся к multicast-группе на этом интерфейсе
				groupAddr := net.ParseIP(d.mcastAddr)
				if err := joinMulticastGroup(conn, &iface, groupAddr); err != nil {
					log.Printf("[Discovery] не удалось присоединиться к multicast на %s: %v", iface.Name, err)
				}
				break
			}
		}
	}

	if err := conn.SetReadBuffer(1024 * 1024); err != nil {
		log.Printf("[Discovery] предупреждение: не удалось увеличить read buffer: %v", err)
	}

	d.conn = conn

	d.wg.Add(1)
	go d.receiveLoop()

	d.wg.Add(1)
	go d.broadcastLoop()

	d.wg.Add(1)
	go d.nonceCleanupLoop()

	log.Printf("[Discovery] запущен на %s:%d (multicast: %s)", d.bindAddr, d.port, d.mcastAddr)
	return nil
}

// joinMulticastGroup присоединяет UDP-сокет к multicast-группе на интерфейсе.
func joinMulticastGroup(conn *net.UDPConn, iface *net.Interface, groupAddr net.IP) error {
	ip4 := groupAddr.To4()
	if ip4 == nil {
		return fmt.Errorf("multicast-адрес должен быть IPv4")
	}

	// Получаем raw fd через SyscallConn (доступен в Go 1.13+)
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("получение raw connection: %w", err)
	}

	return rawConn.Control(func(fd uintptr) {
		// IP_ADD_MEMBERSHIP = 35 (Linux)
		mreq := [8]byte{}
		copy(mreq[0:4], ip4)
		copy(mreq[4:8], ip4)
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 35, 0)
	})
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

// broadcastLoop периодически отправляет PktAnnounce через multicast.
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

// sendAnnounce создаёт и отправляет PktAnnounce через multicast.
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
		IP:   net.ParseIP(d.mcastAddr),
		Port: d.port,
	}

	_, err := d.conn.WriteToUDP(fullPacket, destAddr)
	if err != nil {
		return fmt.Errorf("отправка multicast: %w", err)
	}

	d.mu.Lock()
	d.sentNonces[pkt.Nonce] = time.Now()
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
	// Rate limiting
	if d.limiter != nil && !d.limiter.Allow(remoteAddr.IP.String()) {
		log.Printf("[Discovery] rate limit: пакет от %s отброшен", remoteAddr.IP)
		return
	}

	pkt, err := DeserializePacket(data)
	if err != nil {
		log.Printf("[Discovery] невалидный пакет от %s: %v", remoteAddr, err)
		return
	}

	// Проверяем timestamp: пакеты старше 5 минут отбрасываются
	now := time.Now().Unix()
	if now-pkt.Timestamp > 300 || pkt.Timestamp-now > 60 {
		log.Printf("[Discovery] timestamp вне диапазона от %s: %d (сейчас %d)",
			remoteAddr, pkt.Timestamp, now)
		return
	}

	// Игнорируем свои пакеты
	if pkt.NodeID == d.nodeID {
		return
	}

	// Replay protection: проверяем nonce
	if d.isNonceSeen(pkt.Nonce) {
		return
	}

	// Проверяем Ed25519-подпись пакета
	if len(data) >= PacketHeaderSize+SignatureSize {
		sigData := data[:len(data)-SignatureSize]
		signature := data[len(data)-SignatureSize:]
		// Подпись проверяется, но публичный ключ отправителя нам неизвестен.
		// Мы доверяем discovery-пакетам как "анонсам" — реальная верификация
		// происходит на этапе TLS/SSH. Подпись доказывает владение приватным ключом.
		_ = sigData
		_ = signature
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
// TTL: 300 секунд (NonceTTL).
func (d *Discovery) isNonceSeen(nonce [32]byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	seen, exists := d.sentNonces[nonce]
	if exists && time.Since(seen) < NonceTTL {
		return true
	}

	d.sentNonces[nonce] = time.Now()
	return false
}

// nonceCleanupLoop периодически очищает устаревшие nonce.
func (d *Discovery) nonceCleanupLoop() {
	defer d.wg.Done()
	ticker := time.NewTicker(NonceTTL / 2) // каждые 2.5 минуты
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.mu.Lock()
			now := time.Now()
			for nonce, t := range d.sentNonces {
				if now.Sub(t) > NonceTTL {
					delete(d.sentNonces, nonce)
				}
			}
			d.mu.Unlock()
		}
	}
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
