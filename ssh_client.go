package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

// Параметры probe-обнаружения в `beacon ssh <имя>`.
const (
	// discoveryAnnounceAttempts — сколько broadcast-объявлений уходит за сессию.
	// Одного мало: пакет может уйти в момент, когда сосед ещё не поднялся.
	discoveryAnnounceAttempts = 3

	// discoveryAnnounceInterval — пауза между объявлениями.
	discoveryAnnounceInterval = 200 * time.Millisecond

	// discoveryListenWindow — сколько ждём ответов от соседей.
	discoveryListenWindow = 3 * time.Second
)

// SSHClient — SSH-клиент для подключения к другим маячкам.
type SSHClient struct {
	config     *Config
	trustStore *TrustStore
}

// NewSSHClient создаёт новый SSH-клиент.
func NewSSHClient(cfg *Config) *SSHClient {
	return &SSHClient{config: cfg}
}

// SetTrustStore устанавливает TrustStore для проверки хост-ключей.
func (c *SSHClient) SetTrustStore(ts *TrustStore) {
	c.trustStore = ts
}

// Connect устанавливает SSH-соединение с маячком.
func (c *SSHClient) Connect(target, execCmd string) error {
	addr, err := c.resolveTarget(target)
	if err != nil {
		return fmt.Errorf("разрешение цели %s: %w", target, err)
	}

	keyPath, certPath, _ := c.config.BeaconPaths()
	signer, err := createSSHCertSigner(keyPath, certPath)
	if err != nil {
		return fmt.Errorf("создание SSH signer: %w", err)
	}

	// Проверка host-ключа через TrustStore.
	//
	// Раньше здесь стоял InsecureIgnoreHostKey на случай, если TrustStore не
	// загрузился, — то есть при любой проблеме с CA проверка молча
	// отключалась, и MITM получал сессию. Теперь отсутствие TrustStore — это
	// ошибка: подключаться без возможности проверить host-ключ нельзя.
	if c.trustStore == nil {
		return fmt.Errorf("TrustStore не загружен: проверять host-ключ нечем. " +
			"Проверьте наличие ca/ca-cert.pem в каталоге данных и права на файл")
	}
	hostKeyCallback := ssh.HostKeyCallback(c.trustStore.VerifyHostKey)

	sshConfig := &ssh.ClientConfig{
		User: "beacon",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	log.Printf("[SSH] подключение к %s...", addr)
	conn, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return fmt.Errorf("SSH-подключение к %s: %w", addr, err)
	}
	defer conn.Close()

	log.Printf("[SSH] подключено к %s", addr)

	if execCmd != "" {
		return c.execCommand(conn, execCmd)
	}
	return c.interactiveShell(conn)
}

// execCommand выполняет команду через SSH.
func (c *SSHClient) execCommand(conn *ssh.Client, cmd string) error {
	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("создание сессии: %w", err)
	}
	defer session.Close()

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if err := session.Run(cmd); err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			return fmt.Errorf("команда завершена с кодом %d", exitErr.ExitStatus())
		}
		return fmt.Errorf("выполнение команды: %w", err)
	}

	return nil
}

// interactiveShell открывает интерактивный shell через SSH.
func (c *SSHClient) interactiveShell(conn *ssh.Client) error {
	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("создание сессии: %w", err)
	}
	defer session.Close()

	if !terminal.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("интерактивный shell требует терминал")
	}

	oldState, err := terminal.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("переключение в raw mode: %w", err)
	}
	defer terminal.Restore(int(os.Stdin.Fd()), oldState)

	width, height, _ := terminal.GetSize(int(os.Stdin.Fd()))
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty(os.Getenv("TERM"), height, width, modes); err != nil {
		return fmt.Errorf("запрос PTY: %w", err)
	}

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if err := session.Shell(); err != nil {
		return fmt.Errorf("запуск shell: %w", err)
	}

	sigWinch := make(chan os.Signal, 1)
	signal.Notify(sigWinch, syscall.SIGWINCH)
	defer signal.Stop(sigWinch)

	go func() {
		for range sigWinch {
			w, h, _ := terminal.GetSize(int(os.Stdin.Fd()))
			session.WindowChange(h, w)
		}
	}()

	err = session.Wait()
	if err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			log.Printf("[SSH] shell завершён с кодом %d", exitErr.ExitStatus())
		}
		return err
	}

	return nil
}

// resolveTarget определяет IP:port по имени или адресу.
func (c *SSHClient) resolveTarget(target string) (string, error) {
	if strings.Contains(target, ":") {
		return target, nil
	}

	if net.ParseIP(target) != nil {
		return fmt.Sprintf("%s:%d", target, c.config.SSHPort), nil
	}

	ip, err := c.discoverBeacon(target)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:%d", ip, c.config.SSHPort), nil
}

// discoverBeacon находит IP-адрес маячка по имени через UDP discovery.
//
// Имя разрешается в CN сертификата, а не в то, что сказано по UDP: CN подписан
// CA, поэтому подменить его произвольным пакетом нельзя. Ответ принимается
// только если он подписан ключом из сертификата этого узла — иначе кто угодно
// мог бы прислать пакет с чужим NodeID и увести подключение на свой адрес.
func (c *SSHClient) discoverBeacon(name string) (string, error) {
	if c.trustStore == nil {
		return "", fmt.Errorf("TrustStore не загружен: нечем сопоставить имена узлов с адресами")
	}

	targetCert, err := c.trustStore.CertByCN(name)
	if err != nil {
		// Отозванные сертификаты вообще не попадают в TrustStore, поэтому сюда
		// попадает и «узел отозван» — сообщение обязано называть обе причины.
		return "", fmt.Errorf("узел '%s' не найден среди доверенных сертификатов "+
			"(имя введено с ошибкой или узел отозван): проверьте имя по "+
			"'beacon ca list-trusted -dir %s': %w", name, c.config.DataDir, err)
	}

	if c.trustStore.IsRevoked(targetCert) {
		return "", fmt.Errorf("сертификат узла '%s' отозван: подключение невозможно", name)
	}

	targetPub, err := Ed25519PubFromCert(targetCert)
	if err != nil {
		return "", fmt.Errorf("сертификат узла '%s' не содержит ключа Ed25519 (старый формат): %w",
			name, err)
	}
	targetNodeID := NodeIDFromEd25519Pub(targetPub)

	// Подписываем probe ключом самого маячка: соседи сверяют его с сертификатом,
	// поэтому случайный NodeID здесь недопустим.
	edPriv, err := loadEd25519Key(c.config.Ed25519KeyPath())
	if err != nil {
		return "", fmt.Errorf("загрузка Ed25519-ключа для discovery: %w", err)
	}
	nodeID := NodeIDFromEd25519Pub(edPriv.Public().(ed25519.PublicKey))

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("0.0.0.0")})
	if err != nil {
		return "", fmt.Errorf("не удалось слушать UDP: %w", err)
	}
	defer conn.Close()

	// Чтение идёт параллельно с отправкой: иначе ответ, пришедший на первый
	// announce, ждал бы конца окна прослушивания, а при коротком окне был бы
	// потерян целиком.
	var (
		mu         sync.Mutex
		responders = make(map[string]int)
	)

	collected := make(chan struct{})
	go func() {
		defer close(collected)

		deadline := time.Now().Add(discoveryListenWindow)
		buf := make([]byte, MaxPacketSize)

		for time.Now().Before(deadline) {
			if err := conn.SetReadDeadline(deadline); err != nil {
				return
			}

			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < MinPacketSize {
				continue
			}

			if err := verifyDiscoveryEcho(buf[:n], targetNodeID, targetPub); err != nil {
				log.Printf("[SSH] ответ discovery от %s отброшен: %v", remoteAddr, err)
				continue
			}

			mu.Lock()
			responders[remoteAddr.IP.String()]++
			mu.Unlock()
		}
	}()

	// Рассылаем announce: одного пакета мало — он может попасть в сеть, когда
	// сосед ещё не поднялся, а потерянный UDP не повторяется.
	for i := 0; i < discoveryAnnounceAttempts; i++ {
		if err := c.sendBroadcastDiscovery(conn, edPriv, nodeID); err != nil {
			return "", fmt.Errorf("отправка announce: %w", err)
		}
		time.Sleep(discoveryAnnounceInterval)
	}

	<-collected

	mu.Lock()
	defer mu.Unlock()

	return pickResponderIP(name, responders)
}

// pickResponderIP выбирает адрес среди ответивших узлов.
//
// Один NodeID — один узел: если на него отвечают несколько адресов, в сети клон
// или подмена. Подключаться тогда нельзя, потому что выбор был бы произвольным
// и пользователь об этом не узнал бы.
func pickResponderIP(name string, responders map[string]int) (string, error) {
	switch len(responders) {
	case 0:
		return "", fmt.Errorf("маячок '%s' найден в TrustStore, но не ответил в сети "+
			"(проверьте, что он запущен, находится в этом broadcast-домене, а порт "+
			"discovery совпадает: -disc-port)", name)
	case 1:
		for ip := range responders {
			log.Printf("[SSH] узел '%s' отвечает по %s", name, ip)
			return ip, nil
		}
	}

	ips := make([]string, 0, len(responders))
	for ip := range responders {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	return "", fmt.Errorf("на имя '%s' отвечают несколько адресов (%s): "+
		"вероятно, клон или подмена узла, подключение отменено",
		name, strings.Join(ips, ", "))
}

// verifyDiscoveryEcho проверяет пакет, полученный в ответ на announce.
//
// Подпись сверяется ключом из сертификата целевого узла, а не ключом из
// payload: сертификат подписан CA, поэтому именно он задаёт, кому принадлежит
// узел. Проверка одной лишь NodeID в пакете была бы пустой — её можно
// подделать, записав в пакет чужой идентификатор.
func verifyDiscoveryEcho(data []byte, wantNodeID [16]byte, wantPub ed25519.PublicKey) error {
	if len(data) < PacketHeaderSize+SignatureSize {
		return fmt.Errorf("пакет слишком короткий для подписи: %d байт", len(data))
	}

	pkt, err := DeserializePacket(data)
	if err != nil {
		return err
	}

	if pkt.Type != PktEcho {
		return fmt.Errorf("ожидался PktEcho, получен тип %d", pkt.Type)
	}

	if pkt.NodeID != wantNodeID {
		return fmt.Errorf("NodeID %X не совпадает с целевым %X", pkt.NodeID, wantNodeID)
	}

	payloadPub, err := DeserializeAnnouncePayload(pkt.Payload)
	if err != nil {
		return fmt.Errorf("payload echo: %w", err)
	}

	if !payloadPub.Ed25519Pub.Equal(wantPub) {
		return fmt.Errorf("ключ в payload не совпадает с ключом сертификата")
	}

	sigData := data[:len(data)-SignatureSize]
	signature := data[len(data)-SignatureSize:]
	if !ed25519.Verify(wantPub, sigData, signature) {
		return fmt.Errorf("подпись Ed25519 неверна")
	}

	return nil
}

// sendBroadcastDiscovery отправляет UDP broadcast-пакет с Ed25519-подписью.
//
// Пакет подписывается ключом САМОГО маячка, а не случайным: соседи проверяют
// подпись ключом из нашего сертификата, поэтому announce, подписанный чужим
// ключом, будет отвергнут. Раньше здесь читался путь к ECDSA-ключу, из-за чего
// ключ не загружался и пакет не уходил вообще.
//
// Отправка идёт с ТОГО ЖЕ сокета, на котором клиент слушает ответы. Отдельный
// сокет на DialUDP получал эфемерный порт, и ответ узла уходил именно на него —
// уже закрытый к моменту прихода echo. Из-за этого маячок видел announce,
// отвечал, а `beacon ssh <имя>` упирался в «не ответил в сети».
func (c *SSHClient) sendBroadcastDiscovery(conn *net.UDPConn, edPriv ed25519.PrivateKey, nodeID [16]byte) error {
	payload, err := (&AnnouncePayload{Ed25519Pub: edPriv.Public().(ed25519.PublicKey)}).Serialize()
	if err != nil {
		return fmt.Errorf("формирование announce payload: %w", err)
	}

	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktAnnounce,
		NodeID:    nodeID,
		Timestamp: time.Now().Unix(),
		Payload:   payload,
	}

	if _, err := rand.Read(pkt.Nonce[:]); err != nil {
		return fmt.Errorf("генерация nonce: %w", err)
	}

	addr := &net.UDPAddr{
		IP:   net.ParseIP(c.config.BroadcastAddr),
		Port: c.config.DiscoveryPort,
	}

	if _, err := conn.WriteToUDP(SignPacket(pkt, edPriv), addr); err != nil {
		return fmt.Errorf("отправка на %s: %w", addr, err)
	}

	return nil
}

// loadEd25519Key загружает Ed25519 приватный ключ из PEM-файла.
//
// Файл может быть зашифрован блоком ENCRYPTED BEACON KEY — тогда нужен секрет
// (см. LoadPrivateKeyFile).
func loadEd25519Key(path string) (ed25519.PrivateKey, error) {
	der, err := LoadPrivateKeyFile(path)
	if err != nil {
		return nil, err
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	edKey, ok := parsedKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ключ не Ed25519")
	}
	return edKey, nil
}
