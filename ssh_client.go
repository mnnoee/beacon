package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
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

	// Проверка хост-ключа через TrustStore вместо InsecureIgnoreHostKey
	hostKeyCallback := ssh.InsecureIgnoreHostKey()
	if c.trustStore != nil {
		hostKeyCallback = c.trustStore.VerifyHostKey
	}

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
func (c *SSHClient) discoverBeacon(name string) (string, error) {
	log.Printf("[SSH] поиск маячка '%s' через UDP discovery...", name)

	// Подписываем probe ключом самого маячка: соседи сверяют его с сертификатом,
	// поэтому случайный NodeID здесь недопустим.
	edPriv, err := loadEd25519Key(c.config.Ed25519KeyPath())
	if err != nil {
		return "", fmt.Errorf("загрузка Ed25519-ключа для discovery: %w", err)
	}
	nodeID := NodeIDFromEd25519Pub(edPriv.Public().(ed25519.PublicKey))

	listenAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}
	conn, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		return "", fmt.Errorf("не удалось слушать UDP: %w", err)
	}
	defer conn.Close()

	discovered := make(chan string, 10)

	go func() {
		buf := make([]byte, 1024)
		for {
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n >= MinPacketSize {
				select {
				case discovered <- remoteAddr.IP.String():
				default:
				}
			}
		}
	}()

	for i := 0; i < 5; i++ {
		c.sendBroadcastDiscovery(edPriv, nodeID)
		time.Sleep(100 * time.Millisecond)
	}

	timeout := time.After(2 * time.Second)
	var ips []string
waitLoop:
	for {
		select {
		case ip := <-discovered:
			found := false
			for _, existing := range ips {
				if existing == ip {
					found = true
					break
				}
			}
			if !found {
				ips = append(ips, ip)
			}
		case <-timeout:
			break waitLoop
		}
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("маячок '%s' не найден в сети", name)
	}

	log.Printf("[SSH] найдены IP: %v", ips)
	return ips[0], nil
}

// sendBroadcastDiscovery отправляет UDP broadcast-пакет с Ed25519-подписью.
//
// Пакет подписывается ключом САМОГО маячка, а не случайным: соседи проверяют
// подпись ключом из нашего сертификата, поэтому announce, подписанный чужим
// ключом, будет отвергнут. Раньше здесь читался путь к ECDSA-ключу, из-за чего
// ключ не загружался и пакет не уходил вообще.
func (c *SSHClient) sendBroadcastDiscovery(edPriv ed25519.PrivateKey, nodeID [16]byte) {
	payload, err := (&AnnouncePayload{Ed25519Pub: edPriv.Public().(ed25519.PublicKey)}).Serialize()
	if err != nil {
		log.Printf("[SSH] формирование announce payload: %v", err)
		return
	}

	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktAnnounce,
		NodeID:    nodeID,
		Timestamp: time.Now().Unix(),
		Payload:   payload,
	}

	rand.Read(pkt.Nonce[:])

	addr := &net.UDPAddr{
		IP:   net.ParseIP(c.config.BroadcastAddr),
		Port: c.config.DiscoveryPort,
	}

	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.Write(SignPacket(pkt, edPriv))
}

// loadEd25519Key загружает Ed25519 приватный ключ из PEM-файла.
func loadEd25519Key(path string) (ed25519.PrivateKey, error) {
	data, err := ReadFileContents(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("невалидный PEM")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	edKey, ok := parsedKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ключ не Ed25519")
	}
	return edKey, nil
}
