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
	"path/filepath"
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

	nodeID [16]byte
	edPriv ed25519.PrivateKey
	edPub  ed25519.PublicKey

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

// loadOrCreateEdKey загружает Ed25519-ключ узла.
//
// Ключ больше НЕ создаётся автоматически при первом запуске. Раньше здесь была
// генерация ключа на лету, из-за чего появлялись две несовместимые системы
// идентичности: узел без сертификата получал собственный NodeID и слал
// announce с ключом, которого нет ни в одном сертификате. Теперь ключ выдаётся
// вместе с сертификатом (provision-beacon) и лежит в его SAN, поэтому
// отсутствие файла — это ошибка конфигурации с понятным текстом.
func (b *BeaconNode) loadOrCreateEdKey() error {
	keyPath := b.config.Ed25519KeyPath()

	// Отсутствие файла — ошибка конфигурации, а не повод сгенерировать ключ:
	// ключ выдаётся вместе с сертификатом, и его публичная часть записана в SAN.
	if _, err := os.Stat(keyPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("не найден Ed25519-ключ %s: выдайте сертификат заново командой "+
				"'beacon ca provision-beacon -reissue %s' — ключ выдаётся вместе с сертификатом, "+
				"а его публичная часть записывается в SAN", keyPath, b.config.NodeName)
		}
		return fmt.Errorf("чтение Ed25519 ключа: %w", err)
	}

	// Ключ может быть зашифрован блоком ENCRYPTED BEACON KEY: тогда нужен
	// секрет (см. -passphrase-file / BEACON_PASSPHRASE).
	edDER, err := LoadPrivateKeyFile(keyPath)
	if err != nil {
		return fmt.Errorf("загрузка Ed25519 ключа %s: %w", keyPath, err)
	}

	edKey, err := parseEd25519PrivateKey(edDER)
	if err != nil {
		return fmt.Errorf("разбор Ed25519 ключа %s: %w", keyPath, err)
	}

	b.edPriv = edKey
	b.edPub = edKey.Public().(ed25519.PublicKey)

	// NodeID выводится из ключа детерминированно — так его вычислит и сосед,
	// получив ключ из нашего сертификата.
	b.nodeID = NodeIDFromEd25519Pub(b.edPub)

	// Сверяем ключ с сертификатом: подпись discovery имеет смысл только если
	// сосед сможет найти этот ключ в нашем сертификате.
	_, certPath, _ := b.config.BeaconPaths()
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("чтение сертификата для сверки ключа: %w", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return fmt.Errorf("невалидный PEM сертификата в %s", certPath)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("парсинг сертификата: %w", err)
	}

	certPub, err := Ed25519PubFromCert(cert)
	if err != nil {
		// Сертификат старого формата. Не прерываем запуск: узел должен иметь
		// возможность подняться, чтобы получить новый сертификат. Но в сеть
		// он не попадёт — соседи отвергнут его announce.
		log.Printf("[Beacon] ВНИМАНИЕ: %v", err)
		log.Printf("[Beacon] на CA-машине выполните 'beacon ca provision-beacon -reissue %s' "+
			"и разложите новые файлы в %s", b.config.NodeName, b.config.DataDir)
		return nil
	}

	if !certPub.Equal(b.edPub) {
		return fmt.Errorf("Ed25519-ключ %s не совпадает с ключом в сертификате %s: "+
			"подписи discovery не будут соответствовать сертификату, соседи отвергнут узел",
			keyPath, certPath)
	}

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

	// Discovery всегда слушает 0.0.0.0, а не адрес из -bind.
	//
	// Объявления приходят на broadcast-адрес подсети (192.168.1.255), и сокет,
	// привязанный к одному адресу (192.168.1.166), такой пакет не получает —
	// он доставляется только сокетам, слушающим все адреса. С -bind на
	// конкретный адрес маячок не видел бы соседей вовсе. Адрес из -bind
	// продолжает применяться к TCP-слушателям (TLS и SSH).
	discoveryBind := "0.0.0.0"
	if b.config.DiscoveryBindAddr != "" {
		discoveryBind = b.config.DiscoveryBindAddr
	}

	b.discovery = NewDiscovery(
		b.nodeID, b.edPriv,
		b.config.DiscoveryPort,
		b.config.BroadcastAddr, // единственный режим: broadcast
		discoveryBind,
		limiter,
	)

	// Discovery проверяет сертификаты объявившихся узлов: без TrustStore
	// подпись пакета проверяется только на согласованность с NodeID, что не
	// защищает от подмены.
	b.discovery.SetTrustStore(b.trustStore)
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
//
// По умолчанию SSH выключен. Маячок работает под именем пользователя, который
// его запустил (часто root), и с включённым SSH любой узел сети с сертификатом
// роли server получает shell. Поэтому включать его надо явно, а не по факту
// наличия ключей.
func (b *BeaconNode) startSSHServer() {
	if !b.config.SSHEnabled {
		log.Printf("[Beacon] SSH-сервер выключен (включить: -ssh, разрешить вход: -ssh-allow <CN>)")
		return
	}

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

	allowed := b.config.SSHAllowCNs
	log.Printf("[Beacon] SSH-сервер запущен на порту %d (разрешено CN: %d + собственный)",
		b.config.SSHPort, len(allowed))
}

// StartStateWriter запускает периодическую запись state.json.
//
// Нужен отдельному процессу `beacon monitor`: у него нет доступа к памяти
// маячка, а без адресов пиров он показывает только имена.
func (b *BeaconNode) StartStateWriter() error {
	if err := writeStateFile(b.config, b); err != nil {
		return err
	}

	b.wg.Add(1)
	go b.stateWriterLoop()

	return nil
}

// stateWriterLoop пишет state.json раз в секунду.
func (b *BeaconNode) stateWriterLoop() {
	defer b.wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-b.stopCh:
			return
		case <-ticker.C:
			if err := writeStateFile(b.config, b); err != nil {
				log.Printf("[Beacon] запись state.json: %v", err)
			}
		}
	}
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

	// Собственный NodeID не может быть пиром: это либо наше же broadcast-объявление,
	// вернувшееся на сокет, либо попытка выдать себя за нас.
	if senderID == b.nodeID {
		log.Printf("[Beacon] объявление с собственным NodeID %X от %s проигнорировано",
			senderID, addr)
		return
	}

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

	// Дозваниваемся в ответ на announce и на echo.
	//
	// Раньше звонок шёл только на echo, то есть инициатором всегда был тот,
	// кто получил announce. Два узла, увидевшие друг друга одновременно по
	// announce'ам, оставались без соединения: каждый ждал, что позвонит
	// другой. Теперь dial делает тот, кто обнаружил пира, независимо от
	// типа пакета.
	if !peer.Connected {
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

	// Идентичность пира выводится из его сертификата, а не из SubjectKeyId.
	// Это гарантирует, что discovery-NodeID и NodeID, полученные по TLS,
	// указывают на один и тот же узел.
	peerNodeID, err := NodeIDFromCert(peerCert)
	if err != nil {
		log.Printf("[Beacon] пир %s: %v", addr, err)
		conn.Close()
		return
	}

	// Ключ подписи регистрируется именно здесь — после успешного mTLS.
	// Это и есть TOFU-биндинг: ключ берётся из сертификата, проверенного по
	// CA и CRL, а не из присланного пакета. Поэтому gossip от этого узла
	// можно проверять, а подделать подпись нельзя.
	b.registerPeerSigningKey(peerNodeID, peerCert)

	b.mu.Lock()
	if existing, ok := b.peers[peerNodeID]; ok {
		// Уже есть запись для этого узла — обновляем адрес, не плодим дубликат.
		existing.LastSeen = time.Now()
	} else {
		b.peers[peerNodeID] = &DiscoveredPeer{
			NodeID:       peerNodeID,
			Addr:         peer.Addr,
			DiscoveredAt: time.Now(),
			LastSeen:     time.Now(),
		}
	}
	peer.TLSConn = conn
	peer.Connected = true
	b.mu.Unlock()

	log.Printf("[Beacon] TLS-соединение установлено с %s (CN=%s, nodeID=%X)",
		addr, peerCert.Subject.CommonName, peerNodeID)

	b.handlePeerConnection(peer, conn)
}

// pushGossip отправляет накопленный CRL пиру по установленному соединению.
//
// Работает в обе стороны: и когда мы подключаемся к пиру, и когда пир
// подключается к нам. Иначе gossip был бы односторонним — пир, который сам
// инициировал соединение, наши отзывы так и не узнал бы, а узнать их мог бы
// только ждать 30-минутного цикла.
func (b *BeaconNode) pushGossip(conn *tls.Conn, reason string) {
	// Сначала свой сертификат: без него получатель не сможет ни разрешить
	// наше имя, ни проверить наши подписи gossip.
	_, certPath, _ := b.config.BeaconPaths()
	if err := ShareCertificate(certPath, conn, b.edPriv, b.nodeID); err != nil {
		log.Printf("[Beacon] не удалось отправить сертификат (%s): %v", reason, err)
	}

	entries := b.trustStore.GetRevokedEntries()
	if len(entries) == 0 {
		return
	}

	if err := b.sendGossipToConn(conn, entries); err != nil {
		log.Printf("[Beacon] не удалось отправить gossip (%s) на %s: %v",
			reason, conn.RemoteAddr(), err)
		return
	}

	log.Printf("[Beacon] отправлен gossip (%s) на %s: CRL #%d, записей %d",
		reason, conn.RemoteAddr(), b.trustStore.CRLVersion(), len(entries))
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

	b.pushGossip(conn, "исходящее")

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

		b.handlePeerMessage(buf[:numBytes], peer, buf[:numBytes])
	}
}

// handlePeerMessage обрабатывает сообщение от пира по TLS.
//
// Сообщение приходит по mTLS, поэтому отправитель уже аутентифицирован
// сертификатом, подписанным нашим CA. Дополнительно проверяется подпись
// gossip-пакета ключом отправителя: mTLS гарантирует, что канал открыт именно
// с ним, но не гарантирует, что приложенные данные не подделаны другим
// участником того же туннеля.
func (b *BeaconNode) handlePeerMessage(data []byte, peer *DiscoveredPeer, fullPkt []byte) {
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
		b.handleGossip(pkt, peer, fullPkt)
	case PktCertShare:
		b.handleCertShare(pkt, peer)
	default:
		log.Printf("[Beacon] неизвестный тип сообщения: %d", pkt.Type)
	}
}

// handleCertShare принимает сертификат соседа.
//
// Получение сертификата не равно доверию: проверка идёт по CA и CRL, а
// сохранение лишь добавляет CN в roster. Поэтому прежде чем принимать,
// сверяем, что отправитель — действительно тот, кем представляется.
func (b *BeaconNode) handleCertShare(pkt *DiscoveryPacket, peer *DiscoveredPeer) {
	stored, err := AcceptCertificate(b.config.DataDir, b.trustStore, pkt)
	if err != nil {
		log.Printf("[Beacon] сертификат от %s не принят: %v", peer.Addr, err)
		return
	}

	if stored {
		log.Printf("[Beacon] получен сертификат от %s (CN добавлен в roster)", peer.Addr)
	}
}

// handleGossip обрабатывает gossip-обновление CRL.
//
// Три независимые проверки перед применением:
//  1. подпись пакета ключом Ed25519 отправителя;
//  2. NodeID в пакете совпадает с идентификатором, выведенным из ключа;
//  3. NodeID совпадает с сертификатом пира, по которому установлен mTLS —
//     именно это связывает gossip с тем, кто предъявил сертификат, и не даёт
//     перехватившему mTLS-канал подсунуть свои отзывы.
func (b *BeaconNode) handleGossip(pkt *DiscoveryPacket, peer *DiscoveredPeer, fullPkt []byte) {
	if len(pkt.Payload) == 0 {
		return
	}

	if err := b.verifyGossipSignature(pkt, peer, fullPkt); err != nil {
		log.Printf("[Beacon] gossip от %s отклонён: %v", peer.Addr, err)
		return
	}

	gossip, err := DeserializeGossipPayload(pkt.Payload)
	if err != nil {
		log.Printf("[Beacon] невалидный gossip payload: %v", err)
		return
	}

	if b.trustStore.MergeGossipCRL(gossip.Number, gossip.RevokedEntries) {
		log.Printf("[Beacon] Trust Store обновлён через gossip от %s (CRL #%d, записей: %d)",
			peer.Addr, gossip.Number, len(gossip.RevokedEntries))
	}
}

// verifyGossipSignature проверяет подпись gossip-пакета и соответствие
// отправителя пиру, по которому открыт mTLS-канал.
func (b *BeaconNode) verifyGossipSignature(pkt *DiscoveryPacket, peer *DiscoveredPeer, fullPkt []byte) error {
	if peer == nil {
		return fmt.Errorf("нет контекста пира")
	}

	if len(fullPkt) < MinPacketSize {
		return fmt.Errorf("пакет слишком короткий для проверки подписи: %d байт", len(fullPkt))
	}

	// Ключ отправителя известен из его сертификата — того самого, по которому
	// прошло mTLS-рукопожатие.
	pub, err := b.trustStore.SigningKey(pkt.NodeID)
	if err != nil {
		return fmt.Errorf("ключ подписи отправителя: %w", err)
	}

	sigData := fullPkt[:len(fullPkt)-SignatureSize]
	signature := fullPkt[len(fullPkt)-SignatureSize:]

	if !ed25519.Verify(pub, sigData, signature) {
		return fmt.Errorf("подпись Ed25519 неверна")
	}

	// Отправитель gossip обязан быть тем же, кто открыл TLS-соединение.
	if peer.NodeID != pkt.NodeID {
		return fmt.Errorf("NodeID пакета %X не совпадает с пиром mTLS %X",
			pkt.NodeID, peer.NodeID)
	}

	return nil
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

	// Ключ подписи входящего пира тоже нужно зарегистрировать: без этого
	// его gossip нельзя будет проверить. Аутентификация уже прошла выше.
	if peerNodeID, err := NodeIDFromCert(peerCert); err == nil {
		b.registerPeerSigningKey(peerNodeID, peerCert)
	} else {
		log.Printf("[Beacon] входящий пир %s без ключа подписи: %v",
			peerCert.Subject.CommonName, err)
	}

	go b.handleIncomingConnection(conn, peerCert)
}

// registerPeerSigningKey регистрирует ключ подписи узла после успешной
// аутентификации по mTLS.
//
// Ключ берётся из SAN сертификата, который к этому моменту уже прошёл
// проверку подписи CA и CRL. Отдельная проверка nodeID == f(ключ) обязательна:
// иначе злоумышленник с валидным сертификатом одного узла зарегистрировал бы
// себя под чужим NodeID и подписывал бы gossip от его имени.
func (b *BeaconNode) registerPeerSigningKey(nodeID [16]byte, peerCert *x509.Certificate) {
	pub, err := Ed25519PubFromCert(peerCert)
	if err != nil {
		log.Printf("[Beacon] ключ подписи не извлечён у %s: %v", peerCert.Subject.CommonName, err)
		return
	}

	if got := NodeIDFromEd25519Pub(pub); got != nodeID {
		log.Printf("[Beacon] ВНИМАНИЕ: ключ из сертификата %s даёт nodeID %X, ожидался %X — "+
			"узел не зарегистрирован", peerCert.Subject.CommonName, got, nodeID)
		return
	}

	b.trustStore.RegisterEd25519Key(nodeID, pub)
	log.Printf("[Beacon] ключ подписи узла %s зарегистрирован (nodeID=%X)",
		peerCert.Subject.CommonName, nodeID)
}

// handleIncomingConnection обрабатывает данные от подключившегося пира.
func (b *BeaconNode) handleIncomingConnection(conn *tls.Conn, peerCert *x509.Certificate) {
	defer conn.Close()

	peerAddr, _ := net.ResolveTCPAddr("tcp", conn.RemoteAddr().String())
	udpAddr := &net.UDPAddr{IP: peerAddr.IP, Port: peerAddr.Port}

	// NodeID берётся из ключа Ed25519 в SAN сертификата — тот же расчёт, что
	// делают соседи по discovery-пакетам. Раньше здесь использовался
	// SubjectKeyId, из-за чего пир, найденный по UDP и по TCP, получал разные
	// идентификаторы и две записи в карте пиров.
	peerNodeID, err := NodeIDFromCert(peerCert)
	if err != nil {
		log.Printf("[Beacon] входящее соединение от %s: %v", conn.RemoteAddr(), err)
		return
	}

	// Соединение с самим собой: мы дозвонились до собственного TLS-порта —
	// так бывает, когда сосед с тем же адресом (например, клиент `beacon ssh`
	// на этой же машине) объявился по discovery. Запись собственного сертификата
	// в пиры дала бы в мониторе самого себя и лишнее соединение в карте.
	if peerNodeID == b.nodeID {
		log.Printf("[Beacon] входящее соединение с собственным сертификатом CN=%s — игнорируется",
			peerCert.Subject.CommonName)
		return
	}

	peer := &DiscoveredPeer{
		NodeID: peerNodeID,
		Addr:   udpAddr,
	}

	b.mu.Lock()
	if existing, ok := b.peers[peerNodeID]; ok {
		existing.Connected = true
		existing.TLSConn = conn
		existing.LastSeen = time.Now()
		peer = existing
	} else {
		b.peers[peerNodeID] = peer
	}
	b.mu.Unlock()

	// Отзывы уходят и на входящее соединение: пир, подключившийся к нам
	// сам, должен узнать о них сразу, а не через 30-минутный цикл.
	b.pushGossip(conn, "входящее")

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

		b.handlePeerMessage(buf[:numBytes], peer, buf[:numBytes])
	}
}

// sendGossipToConn отправляет CRL-gossip через TLS-соединение.
func (b *BeaconNode) sendGossipToConn(conn *tls.Conn, entries []revokedCert) error {
	gossipPayload := &GossipPayload{
		Number:         b.trustStore.CRLVersion(),
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
		NodeID:    b.nodeID,
		Timestamp: time.Now().Unix(),
		Payload:   payload,
	}

	if _, err := rand.Read(pkt.Nonce[:]); err != nil {
		return fmt.Errorf("генерация nonce: %w", err)
	}

	if _, err := conn.Write(SignPacket(pkt, b.edPriv)); err != nil {
		return fmt.Errorf("запись gossip: %w", err)
	}

	return nil
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
				if err := b.sendGossipToConn(peer.TLSConn, entries); err != nil {
					log.Printf("[Beacon] gossip на %s не отправлен: %v", peer.Addr, err)
				}
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

	// Каталог ca/ — 0700: сертификат публичный, но лежит он рядом с ключом.
	caDir := filepath.Join(dataDir, "ca")
	if err := os.MkdirAll(caDir, 0700); err != nil {
		return fmt.Errorf("создание каталога %s: %w", caDir, err)
	}

	return os.WriteFile(filepath.Join(caDir, "ca-cert.pem"), data, 0644)
}
