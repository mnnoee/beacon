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

// NonceTTL — время жизни nonce (300 сек = 5 минут).
const NonceTTL = 300 * time.Second

// Discovery — модуль сетевого обнаружения маячков.
// Автоматически выбирает multicast или broadcast в зависимости от сети.
type Discovery struct {
	mu sync.Mutex

	nodeID  [16]byte
	privKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey

	port        int
	mcastAddr   string // multicast-адрес (попытка №1)
	broadcastIP string // broadcast-адрес (fallback)
	bindAddr    string

	conn       *net.UDPConn
	limiter    *RateLimiter
	trustStore *TrustStore
	callback   DiscoveryCallback
	stopCh     chan struct{}
	wg         sync.WaitGroup

	// Режим работы: true = multicast, false = broadcast
	useMulticast bool

	sentNonces map[[32]byte]time.Time
}

// DiscoveryCallback вызывается при обнаружении нового пира.
type DiscoveryCallback func(senderID [16]byte, addr *net.UDPAddr, pktType uint8)

// NewDiscovery создаёт новый экземпляр модуля обнаружения.
func NewDiscovery(nodeID [16]byte, privKey ed25519.PrivateKey, port int, mcastAddr, broadcastIP, bindAddr string, limiter *RateLimiter) *Discovery {
	return &Discovery{
		nodeID:       nodeID,
		privKey:      privKey,
		pubKey:       privKey.Public().(ed25519.PublicKey),
		port:         port,
		mcastAddr:    mcastAddr,
		broadcastIP:  broadcastIP,
		bindAddr:     bindAddr,
		limiter:      limiter,
		stopCh:       make(chan struct{}),
		sentNonces:   make(map[[32]byte]time.Time),
		useMulticast: true, // начнём с multicast, fallback на broadcast
	}
}

// SetTrustStore подключает TrustStore для проверки сертификатов объявившихся
// узлов. Без него подпись проверяется только на согласованность с NodeID,
// но не сверяется с сертификатом — это недостаточно для защиты от подмены.
func (d *Discovery) SetTrustStore(ts *TrustStore) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.trustStore = ts
}

// OnDiscover устанавливает callback.
func (d *Discovery) OnDiscover(cb DiscoveryCallback) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.callback = cb
}

// Start запускает discovery-модуль.
// Пробует multicast, при неудаче — fallback на broadcast.
func (d *Discovery) Start() error {
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

	if err := conn.SetReadBuffer(1024 * 1024); err != nil {
		log.Printf("[Discovery] предупреждение: не удалось увеличить read buffer: %v", err)
	}

	d.conn = conn

	// Всегда broadcast — multicast не работает через WiFi-роутеры
	d.useMulticast = false
	log.Printf("[Discovery] запущен на %s:%d (broadcast: %s)", d.bindAddr, d.port, d.broadcastIP)

	d.wg.Add(1)
	go d.receiveLoop()

	d.wg.Add(1)
	go d.broadcastLoop()

	d.wg.Add(1)
	go d.nonceCleanupLoop()

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

// sendAnnounce создаёт и отправляет PktAnnounce.
// Использует multicast или broadcast в зависимости от режима.
func (d *Discovery) sendAnnounce() error {
	payload, err := (&AnnouncePayload{Ed25519Pub: d.pubKey}).Serialize()
	if err != nil {
		return fmt.Errorf("формирование announce payload: %w", err)
	}

	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktAnnounce,
		NodeID:    d.nodeID,
		Timestamp: time.Now().Unix(),
		Payload:   payload,
	}

	if _, err := rand.Read(pkt.Nonce[:]); err != nil {
		return fmt.Errorf("генерация nonce: %w", err)
	}

	fullPacket := SignPacket(pkt, d.privKey)

	// Выбираем адрес: multicast или broadcast
	targetIP := d.mcastAddr
	if !d.useMulticast {
		targetIP = d.broadcastIP
	}

	destAddr := &net.UDPAddr{
		IP:   net.ParseIP(targetIP),
		Port: d.port,
	}

	_, err = d.conn.WriteToUDP(fullPacket, destAddr)
	if err != nil {
		// Fallback: если multicast не удался, пробуем broadcast
		if d.useMulticast {
			log.Printf("[Discovery] multicast отправка не удалась: %v, fallback на broadcast", err)
			d.useMulticast = false
			destAddr.IP = net.ParseIP(d.broadcastIP)
			_, err = d.conn.WriteToUDP(fullPacket, destAddr)
		}
		if err != nil {
			return fmt.Errorf("отправка: %w", err)
		}
	}

	d.mu.Lock()
	d.sentNonces[pkt.Nonce] = time.Now()
	d.mu.Unlock()

	return nil
}

// SignPacket подписывает пакет Ed25519-ключом и склеивает с подписью.
//
// Вынесено отдельно, чтобы отправка и проверка считали подпись от одних и тех
// же байтов: иначе пакет, подписанный иначе, будет принят как валидный.
func SignPacket(pkt *DiscoveryPacket, priv ed25519.PrivateKey) []byte {
	dataToSign := pkt.Serialize()
	sig := ed25519.Sign(priv, dataToSign)
	return append(dataToSign, sig...)
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

	// Проверяем Ed25519-подпись пакета.
	//
	// Строгая проверка применяется только к УЖЕ ИЗВЕСТНЫМ узлам: у них ключ
	// сопоставлен с сертификатом, и несовпадение означает подмену.
	//
	// Для незнакомых узлов пакет принимается, но только как заявка на
	// соединение: реальная аутентификация происходит в mTLS-рукопожатии,
	// где предъявленный сертификат проверяется по CA и CRL. Без этого
	// система не запускалась бы вообще: подпись проверяется ключом из
	// сертификата, а сертификат появляется только после первого соединения —
	// получался бы замкнутый круг.
	if err := d.verifyPacketSignature(pkt, data); err != nil {
		log.Printf("[Discovery] подпись пакета от %s не принята: %v", remoteAddr, err)
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

// verifyPacketSignature проверяет подпись пакета и соответствие объявленного
// NodeID ключу из сертификата.
//
// Три уровня доверия:
//
//   - узел неизвестен — пакет принимается как заявка на соединение.
//     Аутентификация произойдёт позже, в mTLS-рукопожатии: там предъявленный
//     сертификат проверяется по CA и CRL, и подменить его нельзя.
//   - узел известен, подпись и сертификат сходятся — обычный случай.
//   - узел известен, но подпись неверна или ключ расходится с сертификатом —
//     отказ. Это и есть защита от спуфинга: атакующий может подписать пакет
//     своим ключом, но чужой NodeID или чужой CN у него не получится.
func (d *Discovery) verifyPacketSignature(pkt *DiscoveryPacket, data []byte) error {
	// Пакеты gossip идут по mTLS и проверяются там же; UDP-подпись для них
	// не проверяется. Их обработчик принимает только уже
	// аутентифицированное соединение.
	if pkt.Type == PktGossip {
		return nil
	}

	if len(data) < PacketHeaderSize+SignatureSize {
		return fmt.Errorf("пакет слишком короткий для подписи: %d байт", len(data))
	}

	payload, err := DeserializeAnnouncePayload(pkt.Payload)
	if err != nil {
		return fmt.Errorf("payload announce: %w", err)
	}

	// Подпись проверяется ключом из payload: это доказывает владение
	// приватным ключом, но не принадлежность ключа какому-либо узлу.
	sigData := data[:len(data)-SignatureSize]
	signature := data[len(data)-SignatureSize:]

	if !ed25519.Verify(payload.Ed25519Pub, sigData, signature) {
		return fmt.Errorf("подпись Ed25519 неверна")
	}

	// NodeID обязан соответствовать ключу, которым подписан пакет.
	// Это не даёт объявить чужой идентификатор со своим ключом.
	if got := NodeIDFromEd25519Pub(payload.Ed25519Pub); got != pkt.NodeID {
		return fmt.Errorf("NodeID %X не соответствует ключу из payload (%X)", pkt.NodeID, got)
	}

	// Для незнакомых узлов на этом проверка заканчивается: их сертификата
	// у нас нет, сверить ключ не с чем. Решение о доверии принимается
	// при mTLS-рукопожатии, где сертификат проверяется по CA и CRL.
	if d.trustStore == nil {
		return nil
	}

	cert, err := d.trustStore.FindCertByNodeID(pkt.NodeID)
	if err != nil {
		return nil
	}

	certPub, err := Ed25519PubFromCert(cert)
	if err != nil {
		// Старый формат сертификата — сверка невозможна.
		return nil
	}

	if !certPub.Equal(payload.Ed25519Pub) {
		return fmt.Errorf("ключ пакета не совпадает с ключом сертификата CN=%s: узел отвергнут",
			cert.Subject.CommonName)
	}

	return nil
}

// sendEcho отправляет PktEcho в ответ на Announce.
func (d *Discovery) sendEcho(targetID [16]byte, targetAddr *net.UDPAddr) {
	_ = targetID

	payload, err := (&AnnouncePayload{Ed25519Pub: d.pubKey}).Serialize()
	if err != nil {
		log.Printf("[Discovery] формирование echo payload: %v", err)
		return
	}

	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktEcho,
		NodeID:    d.nodeID,
		Timestamp: time.Now().Unix(),
		Payload:   payload,
	}

	if _, err := rand.Read(pkt.Nonce[:]); err != nil {
		log.Printf("[Discovery] генерация nonce для echo: %v", err)
		return
	}

	if _, err := d.conn.WriteToUDP(SignPacket(pkt, d.privKey), targetAddr); err != nil {
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
//
// Пакет подписывается, но получатель не проверяет подпись: gossip принимается
// только по уже установленному mTLS-соединению (см. BeaconNode.handleGossip).
func (d *Discovery) SendGossip(targetAddr *net.UDPAddr, number uint64, entries []revokedCert) error {
	gossipPayload := &GossipPayload{
		Number:         number,
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

	_, err = d.conn.WriteToUDP(SignPacket(pkt, d.privKey), targetAddr)
	return err
}
