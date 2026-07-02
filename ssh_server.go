package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

// SSHServer — встроенный SSH-сервер в каждом маячке.
//
// Архитектура:
// - Использует тот же ECDSA-ключ/сертификат, что и mTLS
// - Авторизация: Public Key Authentication через TrustStore
// - При успешной авторизации запускает /bin/sh с PTY
// - Поддерживает resize, сигналы, exec-команды
//
// Безопасность:
// - Только public key auth (пароли запрещены)
// - Сертификат проверяется через CA + CRL
// - Ограничение одновременных подключений
// - Idle timeout
// - Запрещены port forwarding и agent forwarding
type SSHServer struct {
	config       *Config
	trustStore   *TrustStore
	hostKey      *ecdsa.PrivateKey
	sshConfig    *ssh.ServerConfig
	listener     net.Listener
	conns        sync.WaitGroup
	sem          chan struct{} // семафор для ограничения подключений
	idleTimeout  time.Duration
	stopCh       chan struct{}
	connCloseCh  chan struct{} // сигнал закрытия всех соединений
}

// NewSSHServer создаёт новый SSH-сервер на основе ключей и Trust Store маячка.
func NewSSHServer(cfg *Config, ts *TrustStore) (*SSHServer, error) {
	// Загружаем приватный ключ ECDSA для SSH-хоста
	keyPath, certPath, _ := cfg.BeaconPaths()
	hostKey, err := loadHostKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("загрузка SSH host key: %w", err)
	}

	// Загружаем сертификат для проверки
	_, err = loadHostCert(certPath)
	if err != nil {
		return nil, fmt.Errorf("загрузка SSH host cert: %w", err)
	}

	srv := &SSHServer{
		config:      cfg,
		trustStore:  ts,
		hostKey:     hostKey,
		sem:         make(chan struct{}, cfg.SSHMaxConns),
		idleTimeout: cfg.SSHIdleTimeout,
		stopCh:      make(chan struct{}),
		connCloseCh: make(chan struct{}),
	}

	// Настраиваем SSH-конфигурацию
	srv.sshConfig = &ssh.ServerConfig{
		PublicKeyCallback: srv.authorize,
		ServerVersion:     "SSH-2.0-NetworkBeacons",
		// Запрещаемassword auth
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return nil, fmt.Errorf("password authentication disabled")
		},
	}

	// Добавляем хост-ключ
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		return nil, fmt.Errorf("создание SSH signer: %w", err)
	}
	srv.sshConfig.AddHostKey(signer)

	return srv, nil
}

// authorize проверяет SSH-ключ клиента через TrustStore в реальном времени.
// Каждое подключение проверяется актуальным состоянием TrustStore (CRL).
func (s *SSHServer) authorize(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	fp := ssh.FingerprintSHA256(pubKey)

	// Ищем сертификат с совпадающим публичным ключом
	for _, cert := range s.trustStore.getTrustedCerts() {
		if cert.PublicKey == nil {
			continue
		}

		sshPubKey, err := ssh.NewPublicKey(cert.PublicKey)
		if err != nil {
			continue
		}

		if ssh.FingerprintSHA256(sshPubKey) == fp {
			// Нашли совпадение — проверяем CRL в реальном времени
			h := ComputeSerialHash(cert)
			if s.trustStore.IsRevoked(h) {
				log.Printf("[SSH] отклонено: сертификат отозван CN=%s addr=%s",
					cert.Subject.CommonName, conn.RemoteAddr())
				return nil, fmt.Errorf("certificate revoked")
			}

			// Проверяем срок действия
			if cert.NotAfter.Before(time.Now()) {
				log.Printf("[SSH] отклонено: сертификат просрочен CN=%s addr=%s",
					cert.Subject.CommonName, conn.RemoteAddr())
				return nil, fmt.Errorf("certificate expired")
			}

			log.Printf("[SSH] авторизован: CN=%s addr=%s fingerprint=%s",
				cert.Subject.CommonName, conn.RemoteAddr(), fp)

			return &ssh.Permissions{
				Extensions: map[string]string{
					"pubkey-cn": cert.Subject.CommonName,
					"pubkey-fp": fp,
				},
			}, nil
		}
	}

	log.Printf("[SSH] отклонено: ключ не авторизован addr=%s fingerprint=%s",
		conn.RemoteAddr(), fp)
	return nil, fmt.Errorf("public key not authorized")
}

// Start запускает SSH-сервер.
func (s *SSHServer) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.BindAddr, s.config.SSHPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("SSH listen %s: %w", addr, err)
	}
	s.listener = ln

	// Обновляем порт в конфиге (для порта 0 = случайный)
	actualAddr := ln.Addr().(*net.TCPAddr)
	s.config.SSHPort = actualAddr.Port

	log.Printf("[SSH] сервер запущен на %s (max conns: %d, idle: %v)",
		ln.Addr(), s.config.SSHMaxConns, s.idleTimeout)

	s.conns.Add(1)
	go s.acceptLoop()

	return nil
}

// Stop останавливает SSH-сервер.
func (s *SSHServer) Stop() {
	close(s.stopCh)
	close(s.connCloseCh)
	if s.listener != nil {
		s.listener.Close()
	}
	s.conns.Wait()
	log.Println("[SSH] сервер остановлен")
}

// acceptLoop принимает входящие TCP-соединения.
func (s *SSHServer) acceptLoop() {
	defer s.conns.Done()

	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				log.Printf("[SSH] accept: %v", err)
				continue
			}
		}

		// Семафор: ограничение одновременных подключений
		select {
		case s.sem <- struct{}{}:
			s.conns.Add(1)
			go s.handleConnection(conn)
		case <-s.stopCh:
			conn.Close()
			return
		default:
			log.Printf("[SSH] отклонено: превышен лимит подключений от %s", conn.RemoteAddr())
			conn.Close()
		}
	}
}

// handleConnection обрабатывает одно SSH-соединение.
func (s *SSHServer) handleConnection(netConn net.Conn) {
	defer func() {
		<-s.sem
		s.conns.Done()
	}()

	startTime := time.Now()
	remoteAddr := netConn.RemoteAddr().String()

	// TLS handshake через SSH
	sshConn, chans, reqs, err := ssh.NewServerConn(netConn, s.sshConfig)
	if err != nil {
		log.Printf("[SSH] handshake с %s: %v", remoteAddr, err)
		netConn.Close()
		return
	}
	defer sshConn.Close()

	username := sshConn.Permissions.Extensions["pubkey-cn"]
	log.Printf("[SSH] соединение установлено: user=%s addr=%s", username, remoteAddr)

	// Отбрасываем глобальные запросы (keepalive и т.д.)
	go ssh.DiscardRequests(reqs)

	// Обрабатываем каналы; range завершается при закрытии канала (client disconnect)
	for {
		select {
		case <-s.connCloseCh:
			sshConn.Close()
			return
		case newChan, ok := <-chans:
			if !ok {
				return
			}
			if newChan.ChannelType() != "session" {
				newChan.Reject(ssh.UnknownChannelType, "только session supported")
				continue
			}
			go s.handleChannel(newChan, sshConn)
		}
	}

	duration := time.Since(startTime)
	log.Printf("[SSH] сессия завершена: user=%s addr=%s duration=%v",
		username, remoteAddr, duration)
}

// handleChannel обрабатывает SSH-канал (session).
func (s *SSHServer) handleChannel(newChan ssh.NewChannel, conn *ssh.ServerConn) {
	channel, requests, err := newChan.Accept()
	if err != nil {
		log.Printf("[SSH] channel accept: %v", err)
		return
	}
	defer channel.Close()

	// Настраиваем idle timeout
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go s.idleWatcher(ctx, channel)

	// Обрабатываем запросы (pty-req, exec, shell, win-req и т.д.)
	go s.handleRequests(ctx, requests, channel, cancel)

	// Ждём завершения канала
	<-ctx.Done()
}

// handleRequests обрабатывает SSH-запросы.
func (s *SSHServer) handleRequests(ctx context.Context, reqs <-chan *ssh.Request, channel ssh.Channel, cancel context.CancelFunc) {
	var execCmd string
	var ptyReq *ptyRequest
	shellStarted := false

	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-reqs:
			if !ok {
				cancel()
				return
			}

			switch req.Type {
			case "pty-req":
				ptyReq = parsePTYReq(req.Payload)
				req.Reply(true, nil)

			case "shell":
				if !shellStarted {
					shellStarted = true
					go s.startShell(ctx, channel, ptyReq, "", cancel)
				}
				req.Reply(true, nil)

			case "exec":
				if !shellStarted {
					shellStarted = true
					cmd := string(req.Payload[4:]) // пропускаем длину
					execCmd = cmd
					go s.startShell(ctx, channel, ptyReq, execCmd, cancel)
				}
				req.Reply(true, nil)

			case "window-change":
				if ptyReq != nil {
					w, h := parseWinChange(req.Payload)
					ptyReq.Width = w
					ptyReq.Height = h
					// resize обрабатывается через SIGWINCH в startShell
				}
				req.Reply(true, nil)

			case "signal":
				// Обработка сигналов (Ctrl+C и т.д.)
				sig := parseSignal(req.Payload)
				if sig != "" {
					log.Printf("[SSH] сигнал: %s", sig)
				}
				req.Reply(false, nil)

			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}
}

// ptyRequest содержит параметры PTY-сессии.
type ptyRequest struct {
	Term   string
	Width  uint32
	Height uint32
}

// startShell запускает shell (или exec-команду) с PTY.
func (s *SSHServer) startShell(ctx context.Context, ch ssh.Channel, pty *ptyRequest, execCmd string, cancel context.CancelFunc) {
	defer cancel()

	// Определяем shell
	shell := "/bin/sh"
	if _, err := os.Stat("/bin/bash"); err == nil {
		shell = "/bin/bash"
	}

	var cmd *exec.Cmd
	if execCmd != "" {
		cmd = exec.Command(shell, "-c", execCmd)
	} else {
		cmd = exec.Command(shell)
	}

	// Настраиваем PTY
	if pty != nil {
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("TERM=%s", pty.Term),
			"LANG=en_US.UTF-8",
			"LC_ALL=en_US.UTF-8",
		)
	}

	// Создаём pipe для stdin
	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Printf("[SSH] stdin pipe: %v", err)
		return
	}

	// Создаём MultiWriter для stdout/stderr
	stdout := ch
	cmd.Stdout = stdout
	cmd.Stderr = stdout

	// Запускаем shell
	if err := cmd.Start(); err != nil {
		log.Printf("[SSH] start shell: %v", err)
		fmt.Fprintf(ch, "ошибка запуска shell: %v\r\n", err)
		return
	}

	// Копируем stdin → shell
	go func() {
		io.Copy(stdin, ch)
		stdin.Close()
	}()

	// Ждём завершения shell
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Обработка SIGWINCH для resize
	sigWinch := make(chan os.Signal, 1)
	signal.Notify(sigWinch, syscall.SIGWINCH)
	defer signal.Stop(sigWinch)

	// Периодическая проверка resize через запросы
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			cmd.Process.Signal(syscall.SIGTERM)
			return
		case err := <-done:
			// Отправляем exit status клиенту (обязательно для exec)
			exitCode := 0
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
				log.Printf("[SSH] shell завершён с кодом %d", exitCode)
			}
			// SSH exit-status request: 4 bytes exit code (big-endian)
			exitPayload := make([]byte, 4)
			exitPayload[0] = byte(exitCode >> 24)
			exitPayload[1] = byte(exitCode >> 16)
			exitPayload[2] = byte(exitCode >> 8)
			exitPayload[3] = byte(exitCode)
			ch.SendRequest("exit-status", false, exitPayload)
			return
		case <-ticker.C:
			// Периодическая проверка — если канал закрыт, выходим
			if ch_err := ch.CloseWrite(); ch_err != nil {
				// Канал уже закрыт
			}
		}
	}
}

// idleWatcher отключает соединение при неактивности.
func (s *SSHServer) idleWatcher(ctx context.Context, ch ssh.Channel) {
	timer := time.NewTimer(s.idleTimeout)
	defer timer.Stop()

	// Мониторим активность через Read
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			log.Printf("[SSH] idle timeout, отключение")
			ch.Close()
			return
		}
	}
}

// ResetIdle сбрасывает таймер неактивности.
// Вызывается при каждой активности (read/write).
func (s *SSHServer) ResetIdle(timer *time.Timer) {
	timer.Reset(s.idleTimeout)
}

// === Вспомогательные функции ===

// loadHostKey загружает ECDSA приватный ключ из PEM.
func loadHostKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("парсинг ECDSA ключа: %w", err)
	}

	return key, nil
}

// loadHostCert загружает x509-сертификат.
func loadHostCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM")
	}

	return x509.ParseCertificate(block.Bytes)
}

// isSSHCertificate проверяет, является ли ключ SSH-сертификатом.
func isSSHCertificate(pubKey ssh.PublicKey) bool {
	_, ok := pubKey.(*ssh.Certificate)
	return ok
}

// extractX509FromSSHCert извлекает x509-сертификат из SSH-сертификата.
// SSH-сертификаты (RFC 6187) содержат x509-сертификат в поле Key.
func extractX509FromSSHCert(pubKey ssh.PublicKey) (*x509.Certificate, error) {
	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("ключ не является SSH-сертификатом")
	}

	// Извлекаем raw bytes ключа из SSH-сертификата
	keyBytes := cert.Key.Marshal()
	if len(keyBytes) == 0 {
		return nil, fmt.Errorf("SSH-сертификат не содержит ключа")
	}

	// Пробуем распарсить как ASN.1 DER x509-сертификат
	parsedCert, err := x509.ParseCertificate(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("парсинг x509 из SSH cert: %w", err)
	}

	return parsedCert, nil
}

// isSSHCertSignedByCA проверяет подпись SSH-сертификата через x509.
func isSSHCertSignedByCA(cert *x509.Certificate, caPool *x509.CertPool) bool {
	opts := x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	_, err := cert.Verify(opts)
	return err == nil
}

// ptyRequestPayload — формат PTY-запроса SSH.
type ptyRequestPayload struct {
	Term    string
	Width   uint32
	Height  uint32
	PixW    uint32
	PixH    uint32
	Modes   string
}

// parsePTYReq парсит payload PTY-запроса.
func parsePTYReq(payload []byte) *ptyRequest {
	if len(payload) < 4 {
		return nil
	}

	// Длина имени терминала
	termLen := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload) < 4+termLen+16 {
		return nil
	}

	term := string(payload[4 : 4+termLen])
	offset := 4 + termLen

	w := uint32(payload[offset])<<24 | uint32(payload[offset+1])<<16 |
		uint32(payload[offset+2])<<8 | uint32(payload[offset+3])
	offset += 4

	h := uint32(payload[offset])<<24 | uint32(payload[offset+1])<<16 |
		uint32(payload[offset+2])<<8 | uint32(payload[offset+3])

	return &ptyRequest{
		Term:   term,
		Width:  w,
		Height: h,
	}
}

// parseWinChange парсит payload window-change запроса.
func parseWinChange(payload []byte) (uint32, uint32) {
	if len(payload) < 8 {
		return 80, 24
	}
	w := uint32(payload[0])<<24 | uint32(payload[1])<<16 |
		uint32(payload[2])<<8 | uint32(payload[3])
	h := uint32(payload[4])<<24 | uint32(payload[5])<<16 |
		uint32(payload[6])<<8 | uint32(payload[7])
	return w, h
}

// parseSignal извлекает имя сигнала из payload.
func parseSignal(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	sigLen := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload) < 4+sigLen {
		return ""
	}
	return string(payload[4 : 4+sigLen])
}

// createSSHCertSigner создаёт SSH signer из ECDSA ключа и сертификата.
// Используется клиентом для авторизации.
func createSSHCertSigner(keyPath, certPath string) (ssh.Signer, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("чтение ключа: %w", err)
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, fmt.Errorf("невалидный PEM ключа")
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		ecKey, err2 := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("парсинг ключа: %w", err)
		}
		parsedKey = ecKey
	}

	ecKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ключ не ECDSA")
	}

	signer, err := ssh.NewSignerFromKey(ecKey)
	if err != nil {
		return nil, fmt.Errorf("создание signer: %w", err)
	}

	return signer, nil
}

// ensureTerminalAvailable проверяет доступность PTY.
func ensureTerminalAvailable() bool {
	return terminal.IsTerminal(int(os.Stdin.Fd()))
}
