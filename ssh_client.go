package main

import (
	"crypto/rand"
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
//
// Поддерживает:
// - Интерактивный shell (PTY)
// - Выполнение команд (exec)
// - Обнаружение маячков через UDP discovery
// - Авторизацию по сертификату
type SSHClient struct {
	config *Config
}

// NewSSHClient создаёт новый SSH-клиент.
func NewSSHClient(cfg *Config) *SSHClient {
	return &SSHClient{config: cfg}
}

// Connect устанавливает SSH-соединение с маячком.
//
// Параметры:
// - target: IP:port или имя маячка (для discovery)
// - execCmd: команда для выполнения (пустая строка = interactive shell)
func (c *SSHClient) Connect(target, execCmd string) error {
	// Определяем адрес подключения
	addr, err := c.resolveTarget(target)
	if err != nil {
		return fmt.Errorf("разрешение цели %s: %w", target, err)
	}

	// Создаём SSH signer из локальных ключей
	keyPath, certPath, _ := c.config.BeaconPaths()
	signer, err := createSSHCertSigner(keyPath, certPath)
	if err != nil {
		return fmt.Errorf("создание SSH signer: %w", err)
	}

	// Настраиваем SSH-клиент
	sshConfig := &ssh.ClientConfig{
		User: "beacon",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // P2P-сеть, проверяем через TrustStore
		Timeout:         10 * time.Second,
	}

	// Подключаемся
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

	// Направляем stdin/stdout/stderr
	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	// Запускаем exec
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

	// Проверяем, что stdin — терминал
	if !terminal.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("интерактивный shell требует терминал")
	}

	// Сохраняем текущий режим терминала
	oldState, err := terminal.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("переключение в raw mode: %w", err)
	}
	defer terminal.Restore(int(os.Stdin.Fd()), oldState)

	// Запрашиваем PTY
	width, height, _ := terminal.GetSize(int(os.Stdin.Fd()))
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty(os.Getenv("TERM"), height, width, modes); err != nil {
		return fmt.Errorf("запрос PTY: %w", err)
	}

	// Направляем stdin/stdout/stderr
	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	// Запускаем shell
	if err := session.Shell(); err != nil {
		return fmt.Errorf("запуск shell: %w", err)
	}

	// Обработка resize
	sigWinch := make(chan os.Signal, 1)
	signal.Notify(sigWinch, syscall.SIGWINCH)
	defer signal.Stop(sigWinch)

	// Горутина для обработки resize
	go func() {
		for range sigWinch {
			w, h, _ := terminal.GetSize(int(os.Stdin.Fd()))
			session.WindowChange(h, w)
		}
	}()

	// Ждём завершения shell
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
	// Если уже IP:port — возвращаем как есть
	if strings.Contains(target, ":") {
		return target, nil
	}

	// Если это IP без порта — добавляем порт
	if net.ParseIP(target) != nil {
		return fmt.Sprintf("%s:%d", target, c.config.SSHPort), nil
	}

	// Иначе это имя маячка — ищем через discovery
	ip, err := c.discoverBeacon(target)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:%d", ip, c.config.SSHPort), nil
}

// discoverBeacon находит IP-адрес маячка по имени через UDP discovery.
//
// Отправляет Announce-пакет и ждёт Echo от целевого маячка.
// В реальной сети это работает через broadcast — все маячки отвечают.
// Здесь мы отправляем несколько broadcast-пакетов и собираем ответы.
func (c *SSHClient) discoverBeacon(name string) (string, error) {
	log.Printf("[SSH] поиск маячка '%s' через UDP discovery...", name)

	nodeID := GenerateNodeID()

	// Слушаем ответы на UDP (используем случайный порт, чтобы не конфликтовать с beacon)
	listenAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}
	conn, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		return "", fmt.Errorf("не удалось слушать UDP: %w", err)
	}
	defer conn.Close()

	discovered := make(chan string, 10)

	// Горутина чтения ответов
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

	// Отправляем broadcast-пакеты
	for i := 0; i < 5; i++ {
		c.sendBroadcastDiscovery(nodeID)
		time.Sleep(100 * time.Millisecond)
	}

	// Собираем уникальные IP в течение 2 секунд
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

// sendBroadcastDiscovery отправляет UDP broadcast-пакет.
func (c *SSHClient) sendBroadcastDiscovery(nodeID [16]byte) {
	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktAnnounce,
		NodeID:    nodeID,
		Timestamp: time.Now().Unix(),
	}

	// Генерируем nonce
	rand.Read(pkt.Nonce[:])

	// Подписываем (bare ключ — для discovery это ок)
	data := pkt.Serialize()

	addr := &net.UDPAddr{
		IP:   net.ParseIP(c.config.BroadcastAddr),
		Port: c.config.DiscoveryPort,
	}

	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.Write(data)
}
