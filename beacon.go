package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// BeaconNode — основной узел системы «Сетевые Маячки».
//
// Жизненный цикл:
// 1. Инициализация: загрузка ключей, сертификатов, Trust Store
// 2. Discovery: UDP-обнаружение пиров в локальной сети
// 3. Handshake: TLS-соединение с обнаруженным пиром
// 4. Verification: проверка сертификата пира через Trust Store
// 5. Communication: защищённый P2P-обмен данными
// 6. Gossip: обмен обновлениями CRL с пиром

// DiscoveredPeer — информация об обнаруженном пире.
type DiscoveredPeer struct {
	NodeID       [16]byte
	Addr         *net.UDPAddr
	DiscoveredAt time.Time
	LastSeen     time.Time
	Connected    bool
	TLSConn      *tls.Conn
}

// BeaconNode основная структура маячка.
type BeaconNode struct {
	mu sync.RWMutex

	config *Config

	nodeID   [16]byte
	edPriv   ed25519.PrivateKey
	edPub    ed25519.PublicKey

	tlsServerConfig *tls.Config
	tlsClientConfig *tls.Config
	cert            *x509.Certificate

	trustStore *TrustStore
	discovery  *Discovery
	sshServer  *SSHServer

	peers map[[16]byte]*DiscoveredPeer

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewBeaconNode создаёт и инициализирует новый Beacon Node.
func NewBeaconNode(cfg *Config) (*BeaconNode, error) {
	node := &BeaconNode{
		config: cfg,
		peers:  make(map[[16]byte]*DiscoveredPeer),
		stopCh: make(chan struct{}),
	}

	if err := node.loadOrCreateEdKey(); err != nil {
		return nil, fmt.Errorf("инициализация ключей: %w", err)
	}

	// TrustStore загружается ДО TLS, т.к. TLSClientConfig проверяет
	// сертификаты пиров через TrustStore
	if err := node.loadTrustStore(); err != nil {
		return nil, fmt.Errorf("загрузка Trust Store: %w", err)
	}

	if err := node.loadTLSConfig(); err != nil {
		return nil, fmt.Errorf("инициализация TLS: %w", err)
	}

	log.Printf("[Beacon] узел инициализирован: ID=%X CN=%s", node.nodeID, node.config.NodeName)
	return node, nil
}

// loadOrCreateEdKey загружает Ed25519-ключ или генерирует новый.
func (b *BeaconNode) loadOrCreateEdKey() error {
	keyPath := b.config.DataDir + "/" + b.config.NodeName + "/ed25519-key.pem"

	data, err := ReadFileContents(keyPath)
	if err != nil {
		return fmt.Errorf("чтение Ed25519 ключа: %w", err)
	}

	if data != nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return fmt.Errorf("невалидный PEM Ed25519 ключа")
		}
		priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("парсинг Ed25519 ключа: %w", err)
		}
		edKey, ok := priv.(ed25519.PrivateKey)
		if !ok {
			return fmt.Errorf("ключ не Ed25519")
		}
		b.edPriv = edKey
		b.edPub = edKey.Public().(ed25519.PublicKey)
		b.nodeID = [16]byte(b.edPub[:16])
		return nil
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("генерация Ed25519 ключа: %w", err)
	}
	b.edPriv = priv
	b.edPub = pub

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("маршализация ключа: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})
	if err := SaveKeyToFile(keyPath, privPEM); err != nil {
		return fmt.Errorf("сохранение Ed25519 ключа: %w", err)
	}

	b.nodeID = [16]byte(pub[:16])
	return nil
}

// loadTLSConfig загружает TLS-сертификат и создаёт конфигурации.
func (b *BeaconNode) loadTLSConfig() error {
	keyPath, certPath, caPath := b.config.BeaconPaths()

	serverConfig, err := TLSConfigForNode(certPath, keyPath, caPath)
	if err != nil {
		return err
	}
	b.tlsServerConfig = serverConfig

	clientConfig, err := TLSClientConfig(certPath, keyPath, caPath, b.trustStore)
	if err != nil {
		return err
	}
	b.tlsClientConfig = clientConfig

	certData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("чтение TLS-сертификата: %w", err)
	}
	block, _ := pem.Decode(certData)
	if block == nil {
		return fmt.Errorf("невалидный PEM TLS-сертификата")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("парсинг TLS-сертификата: %w", err)
	}
	b.cert = cert

	return nil
}

// loadTrustStore загружает Trust Store.
func (b *BeaconNode) loadTrustStore() error {
	_, _, caPath := b.config.BeaconPaths()
	crlPath := b.config.DataDir + "/ca/crl.pem"

	ts, err := NewTrustStore(caPath, crlPath)
	if err != nil {
		return err
	}
	b.trustStore = ts

	// Загружаем Ed25519 ключи для проверки gossip-подписей
	b.trustStore.RegisterEd25519KeyFromDisk(b.config.DataDir)

	return nil
}

// Start запускает все подсистемы маячка.
func (b *BeaconNode) Start() error {
	limiter := NewRateLimiter(b.config.RateLimitRate, b.config.RateLimitBurst)
	b.discovery = NewDiscovery(
		b.nodeID, b.edPriv,
		b.config.DiscoveryPort,
		"239.19.84.1",           // multicast (попытка №1)
		b.config.BroadcastAddr,  // broadcast (основной режим)
		b.config.BindAddr,
		limiter,
	)
	// Начинаем с broadcast — multicast не работает через WiFi-роутеры
	b.discovery.useMulticast = false

	b.discovery.OnDiscover(b.onPeerDiscovered)

	if err := b.discovery.Start(); err != nil {
		return fmt.Errorf("запуск discovery: %w", err)
	}

	b.wg.Add(1)
	go b.tlsServerLoop()

	b.wg.Add(1)
	go b.gossipLoop()

	b.wg.Add(1)
	go b.healthCheckLoop()

	// Запускаем SSH-сервер
	b.startSSHServer()

	log.Println("[Beacon] узел запущен и готов к обнаружению")
	return nil
}

// startSSHServer запускает встроенный SSH-сервер.
func (b *BeaconNode) startSSHServer() {
	sshSrv, err := NewSSHServer(b.config, b.trustStore)
	if err != nil {
		log.Printf("[Beacon] не удалось создать SSH-сервер: %v", err)
		return
	}

	b.sshServer = sshSrv
	if err := sshSrv.Start(); err != nil {
		log.Printf("[Beacon] не удалось запустить SSH-сервер: %v", err)
		b.sshServer = nil
		return
	}

	log.Printf("[Beacon] SSH-сервер запущен на порту %d", b.config.SSHPort)
}

// Stop останавливает все подсистемы.
func (b *BeaconNode) Stop() {
	close(b.stopCh)
	if b.discovery != nil {
		b.discovery.Stop()
	}
	if b.sshServer != nil {
		b.sshServer.Stop()
	}

	b.mu.Lock()
	for _, peer := range b.peers {
		if peer.TLSConn != nil {
			peer.TLSConn.Close()
		}
	}
	b.mu.Unlock()

	b.wg.Wait()
	log.Println("[Beacon] узел остановлен")
}

// onPeerDiscovered вызывается при обнаружении нового пира.
func (b *BeaconNode) onPeerDiscovered(senderID [16]byte, addr *net.UDPAddr, pktType uint8) {
	b.mu.Lock()
	defer b.mu.Unlock()

	peer, exists := b.peers[senderID]
	if !exists {
		log.Printf("[Beacon] обнаружен новый пир: ID=%X addr=%s type=%d",
			senderID, addr, pktType)
		peer = &DiscoveredPeer{
			NodeID:       senderID,
			Addr:         addr,
			DiscoveredAt: time.Now(),
		}
		b.peers[senderID] = peer
	}

	peer.LastSeen = time.Now()

	if pktType == PktEcho && !peer.Connected {
		go b.connectToPeer(peer)
	}
}

// connectToPeer устанавливает TLS-соединение с пиром.
func (b *BeaconNode) connectToPeer(peer *DiscoveredPeer) {
	addr := fmt.Sprintf("%s:%d", peer.Addr.IP.String(), b.config.TLSPort)

	conn, err := TLSClientDial(addr, b.tlsClientConfig)
	if err != nil {
		log.Printf("[Beacon] TLS-подключение к %s не удалось: %v", addr, err)
		return
	}

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Printf("[Beacon] пир %s не предоставил сертификат", addr)
		conn.Close()
		return
	}

	peerCert := state.PeerCertificates[0]

	if !b.trustStore.IsTrusted(peerCert) {
		log.Printf("[Beacon] сертификат пира %s не доверен (CN=%s)", addr, peerCert.Subject.CommonName)
		conn.Close()
		return
	}

	b.mu.Lock()
	peer.TLSConn = conn
	peer.Connected = true
	b.mu.Unlock()

	log.Printf("[Beacon] TLS-соединение установлено с %s (CN=%s)",
		addr, peerCert.Subject.CommonName)

	b.handlePeerConnection(peer, conn)
}

// handlePeerConnection обрабатывает активное TLS-соединение с пиром.
func (b *BeaconNode) handlePeerConnection(peer *DiscoveredPeer, conn *tls.Conn) {
	defer func() {
		conn.Close()
		b.mu.Lock()
		peer.Connected = false
		peer.TLSConn = nil
		b.mu.Unlock()
		log.Printf("[Beacon] соединение с %s разорвано", peer.Addr)
	}()

	// Отправляем gossip при первом подключении
	entries := b.trustStore.GetRevokedEntries()
	if len(entries) > 0 {
		b.sendGossipToConn(conn, entries)
	}

	buf := make([]byte, MaxPacketSize)
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	for {
		select {
		case <-b.stopCh:
			return
		default:
		}

		numBytes, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("[Beacon] чтение от пира: %v", err)
			return
		}

		b.handlePeerMessage(buf[:numBytes], peer)
	}
}

// handlePeerMessage обрабатывает сообщение от пира по TLS.
func (b *BeaconNode) handlePeerMessage(data []byte, peer *DiscoveredPeer) {
	if len(data) < MinPacketSize {
		return
	}

	pkt, err := DeserializePacket(data)
	if err != nil {
		log.Printf("[Beacon] невалидное сообщение от пира: %v", err)
		return
	}

	switch pkt.Type {
	case PktGossip:
		b.handleGossip(pkt, peer)
	default:
		log.Printf("[Beacon] неизвестный тип сообщения: %d", pkt.Type)
	}
}

// handleGossip обрабатывает gossip-обновление CRL.
func (b *BeaconNode) handleGossip(pkt *DiscoveryPacket, peer *DiscoveredPeer) {
	if len(pkt.Payload) == 0 {
		return
	}

	gossip, err := DeserializeGossipPayload(pkt.Payload)
	if err != nil {
		log.Printf("[Beacon] невалидный gossip payload: %v", err)
		return
	}

	if b.trustStore.MergeGossipCRL(gossip.CRLVersion, gossip.RevokedEntries) {
		log.Printf("[Beacon] Trust Store обновлен через gossip от %s (версия CRL: %d, новых записей: %d)",
			peer.Addr, gossip.CRLVersion, len(gossip.RevokedEntries))
	}
}

// tlsServerLoop принимает TLS-соединения от других маячков.
func (b *BeaconNode) tlsServerLoop() {
	defer b.wg.Done()

	addr := fmt.Sprintf("%s:%d", b.config.BindAddr, b.config.TLSPort)
	ln, err := TLSServerListener(addr, b.tlsServerConfig)
	if err != nil {
		log.Printf("[Beacon] ошибка запуска TLS-сервера: %v", err)
		return
	}
	defer ln.Close()

	for {
		select {
		case <-b.stopCh:
			return
		default:
		}

		connCh := make(chan net.Conn, 1)
		errCh := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				errCh <- err
			} else {
				connCh <- conn
			}
		}()

		select {
		case <-b.stopCh:
			return
		case conn := <-connCh:
			b.handleIncomingTLS(conn.(*tls.Conn))
		case err := <-errCh:
			log.Printf("[Beacon] ошибка accept: %v", err)
		}
	}
}

// handleIncomingTLS обрабатывает входящее TLS-соединение.
// В Go TLS handshake ленивый — выполняется при первом Read/Write.
// Обязательно вызываем Handshake() до проверки сертификатов.
func (b *BeaconNode) handleIncomingTLS(conn *tls.Conn) {
	if err := conn.Handshake(); err != nil {
		log.Printf("[Beacon] TLS handshake не удался с %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Printf("[Beacon] входящее соединение без сертификата от %s", conn.RemoteAddr())
		conn.Close()
		return
	}

	peerCert := state.PeerCertificates[0]

	if !b.trustStore.IsTrusted(peerCert) {
		log.Printf("[Beacon] отклонено входящее соединение: сертификат не доверен (CN=%s)",
			peerCert.Subject.CommonName)
		conn.Close()
		return
	}

	log.Printf("[Beacon] принято TLS-соединение от %s (CN=%s)",
		conn.RemoteAddr(), peerCert.Subject.CommonName)

	go b.handleIncomingConnection(conn, peerCert)
}

// handleIncomingConnection обрабатывает данные от подключившегося пира.
func (b *BeaconNode) handleIncomingConnection(conn *tls.Conn, peerCert *x509.Certificate) {
	defer conn.Close()

	peerAddr, _ := net.ResolveTCPAddr("tcp", conn.RemoteAddr().String())
	udpAddr := &net.UDPAddr{IP: peerAddr.IP, Port: peerAddr.Port}

	peer := &DiscoveredPeer{
		NodeID: [16]byte(peerCert.SubjectKeyId),
		Addr:   udpAddr,
	}

	buf := make([]byte, MaxPacketSize)
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	for {
		select {
		case <-b.stopCh:
			return
		default:
		}

		numBytes, err := conn.Read(buf)
		if err != nil {
			return
		}

		b.handlePeerMessage(buf[:numBytes], peer)
	}
}

// sendGossipToConn отправляет CRL-гossip через TLS-соединение.
func (b *BeaconNode) sendGossipToConn(conn *tls.Conn, entries []RevokedEntry) {
	gossipPayload := &GossipPayload{
		CRLVersion:     b.trustStore.CRLVersion(),
		RevokedEntries: entries,
	}
	payload, _ := SerializeGossipPayload(gossipPayload)
	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktGossip,
		NodeID:    b.nodeID,
		Timestamp: time.Now().Unix(),
		Payload:   payload,
	}
	if _, err := rand.Read(pkt.Nonce[:]); err != nil {
		return
	}
	dataToSign := pkt.Serialize()
	sig := ed25519.Sign(b.edPriv, dataToSign)
	fullPacket := append(dataToSign, sig...)
	conn.Write(fullPacket)
}

// gossipLoop периодически рассылает CRL всем подключённым пиром.
func (b *BeaconNode) gossipLoop() {
	defer b.wg.Done()

	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-b.stopCh:
			return
		case <-ticker.C:
			b.mu.RLock()
			activePeers := make([]*DiscoveredPeer, 0)
			for _, peer := range b.peers {
				if peer.Connected && peer.TLSConn != nil {
					activePeers = append(activePeers, peer)
				}
			}
			b.mu.RUnlock()

			entries := b.trustStore.GetRevokedEntries()
			if len(entries) == 0 {
				continue
			}

			for _, peer := range activePeers {
				b.sendGossipToConn(peer.TLSConn, entries)
			}
		}
	}
}

// healthCheckLoop проверяет состояние пиров и удаляет неактивных.
func (b *BeaconNode) healthCheckLoop() {
	defer b.wg.Done()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-b.stopCh:
			return
		case <-ticker.C:
			b.mu.Lock()
			for id, peer := range b.peers {
				if time.Since(peer.LastSeen) > 5*time.Minute {
					log.Printf("[Beacon] пир %X неактивен, удаляем", id)
					if peer.TLSConn != nil {
						peer.TLSConn.Close()
					}
					delete(b.peers, id)
				}
			}
			b.mu.Unlock()
		}
	}
}

// Stats возвращает статистику работы маячка.
func (b *BeaconNode) Stats() map[string]interface{} {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return map[string]interface{}{
		"node_id": fmt.Sprintf("%X", b.nodeID),
		"cn":      b.config.NodeName,
		"peers":   len(b.peers),
		"crl_ver": b.trustStore.CRLVersion(),
	}
}

// ImportCACert импортирует CA-сертификат из файла (для offline-provisioning).
func ImportCACert(dataDir, caCertPath string) error {
	data, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("чтение CA-сертификата: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("невалидный PEM CA-сертификата")
	}

	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("парсинг CA-сертификата: %w", err)
	}

	return SaveKeyToFile(dataDir+"/ca/ca-cert.pem", data)
}
