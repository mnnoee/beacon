package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	// Определяем подкоманды через первый аргумент
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "ca":
		cmdCA(os.Args[2:])
	case "beacon":
		cmdBeacon(os.Args[2:])
	case "ssh":
		cmdSSH(os.Args[2:])
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "неизвестная команда: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Network Beacons — распределенная система поиска устройств в локальной сети

Использование:
  beacon ca <команда>       — операции Главной Ноды (CA)
  beacon beacon             — запуск Маячка
  beacon ssh <цель>         — SSH-подключение к маячку

Команды CA:
  generate-ca              — генерация корневого CA
  provision-beacon <имя>   — выдача сертификата новому маячку
  revoke-beacon <serial>   — отзыв сертификата маячка
  list-trusted             — список доверенных узлов
  import-ca <путь>         — импорт CA-сертификата из файла

SSH:
  beacon ssh <ip:port>     — подключение по IP
  beacon ssh <имя>         — подключение по имени (через discovery)
  beacon ssh <ip> "cmd"    — выполнение команды

Примеры:
  # Сгенерировать CA
  beacon ca generate-ca

  # Выдать сертификат для нового маячка
  beacon ca provision-beacon beacon-node-1

  # Запустить маячок
  beacon beacon -name beacon-node-1 -bind 0.0.0.0

  # Подключиться по SSH
  beacon ssh 192.168.1.10
  beacon ssh beacon-nas

  # Выполнить команду
  beacon ssh 192.168.1.10 "uname -a"

  # Отозвать сертификат
  beacon ca revoke-beacon <serial-hash-hex>

Защита:
  - Все соединения защищены Mutual TLS (взаимная аутентификация)
  - UDP discovery-пакеты подписываются Ed25519
  - Защита от replay-атак (nonce + timestamp)
  - Rate limiting для защиты от UDP-флуда
   - Ключи хранятся на диске с ограничением прав (0600)`)
}

// cmdSSH обрабатывает SSH-подключения к маячкам.
func cmdSSH(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "укажите цель: beacon ssh <ip:port | имя-маячка> [команда]")
		os.Exit(1)
	}

	fs := flag.NewFlagSet("ssh", flag.ExitOnError)
	dataDir := fs.String("dir", "./beacon-data", "директория с данными")
	nodeName := fs.String("name", "", "имя этого маячка (для аутентификации)")
	sshPort := fs.Int("p", 0, "порт SSH (переопределяет авто)")

	fs.Parse(args)

	target := fs.Arg(0)
	execCmd := fs.Arg(1) // может быть пустым

	if target == "" {
		fmt.Fprintln(os.Stderr, "укажите цель: beacon ssh -name <имя> <ip:port | имя-маячка> [команда]")
		os.Exit(1)
	}

	cfg := DefaultConfig()
	cfg.DataDir = *dataDir
	cfg.NodeName = *nodeName
	if *sshPort > 0 {
		cfg.SSHPort = *sshPort
	}

	client := NewSSHClient(cfg)
	if err := client.Connect(target, execCmd); err != nil {
		fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
		os.Exit(1)
	}
}

// cmdCA обрабатывает команды Главной Ноды (CA).
func cmdCA(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "укажите подкоманду: generate-ca, provision-beacon, revoke-beacon, list-trusted, import-ca")
		os.Exit(1)
	}

	subCmd := args[0]
	fs := flag.NewFlagSet("ca-"+subCmd, flag.ExitOnError)

	dataDir := fs.String("dir", "./beacon-data", "директория с данными CA")
	caKeyPath := fs.String("ca-key", "", "путь к ключу CA (авто)")
	caCertPath := fs.String("ca-cert", "", "путь к сертификату CA (авто)")

	fs.Parse(args[1:])

	// Автоопределение путей
	if *caKeyPath == "" {
		*caKeyPath = *dataDir + "/ca/ca-key.pem"
	}
	if *caCertPath == "" {
		*caCertPath = *dataDir + "/ca/ca-cert.pem"
	}

	switch subCmd {
	case "generate-ca":
		cmdGenerateCA(*dataDir, *caKeyPath, *caCertPath)

	case "provision-beacon":
		if fs.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "укажите имя маячка: beacon ca provision-beacon <имя>")
			os.Exit(1)
		}
		nodeName := fs.Arg(0)
		cmdProvisionBeacon(*dataDir, *caKeyPath, *caCertPath, nodeName)

	case "revoke-beacon":
		if fs.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "укажите serial hash: beacon ca revoke-beacon <hex-serial>")
			os.Exit(1)
		}
		serialHex := fs.Arg(0)
		cmdRevokeBeacon(*dataDir, serialHex)

	case "list-trusted":
		cmdListTrusted(*dataDir)

	case "import-ca":
		if fs.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "укажите путь к CA-сертификату: beacon ca import-ca <путь>")
			os.Exit(1)
		}
		cmdImportCA(*dataDir, fs.Arg(0))

	default:
		fmt.Fprintf(os.Stderr, "неизвестная подкоманда CA: %s\n", subCmd)
		os.Exit(1)
	}
}

// cmdGenerateCA генерирует корневой CA.
func cmdGenerateCA(dataDir, caKeyPath, caCertPath string) {
	fmt.Println("Генерация корневого Certificate Authority...")

	// Проверяем, не существует ли уже CA
	if _, err := os.Stat(caKeyPath); err == nil {
		fmt.Fprintf(os.Stderr, "CA уже существует: %s\n", caKeyPath)
		fmt.Fprintln(os.Stderr, "для пересоздания удалите директорию ca/ в", dataDir)
		os.Exit(1)
	}

	_, certPEM, err := GenerateCA(dataDir, DefaultCALifetime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка генерации CA: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("CA успешно сгенерирован:")
	fmt.Printf("  Ключ:    %s (права 0600)\n", caKeyPath)
	fmt.Printf("  Сертификат: %s\n", caCertPath)
	fmt.Println()
	fmt.Println("ВАЖНО: бэкапите ключ CA в безопасном месте!")
	fmt.Println("При его утрате вы не сможете выдавать новые сертификаты.")
	fmt.Println()
	fmt.Println("Сертификат CA (распространяйте среди маячков):")
	fmt.Println(string(certPEM))
}

// cmdProvisionBeacon выдаёт сертификат новому маячку.
func cmdProvisionBeacon(dataDir, caKeyPath, caCertPath, nodeName string) {
	fmt.Printf("Выдача сертификата для маячка: %s\n", nodeName)

	// Валидация имени
	if len(nodeName) < 3 || len(nodeName) > 63 {
		fmt.Fprintln(os.Stderr, "имя должно быть от 3 до 63 символов")
		os.Exit(1)
	}
	if !strings.HasPrefix(nodeName, "beacon-") {
		nodeName = "beacon-" + nodeName
		fmt.Printf("  (добавлен префикс: %s)\n", nodeName)
	}

	// Загружаем CA
	caKey, err := LoadCAKey(caKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "загрузка ключа CA: %v\n", err)
		os.Exit(1)
	}

	caCertData, err := os.ReadFile(caCertPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "чтение сертификата CA: %v\n", err)
		os.Exit(1)
	}

	// Генерируем Node ID
	nodeID := GenerateNodeID()

	// Выдаём сертификат
	certPath, keyPath, err := IssueCertificate(caKey, caCertData, dataDir, nodeName, nodeID, DefaultCertTTL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка выдачи сертификата: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Сертификат успешно выдан:")
	fmt.Printf("  Node ID:    %X\n", nodeID)
	fmt.Printf("  Сертификат: %s\n", certPath)
	fmt.Printf("  Ключ:       %s (права 0600)\n", keyPath)
	fmt.Println()
	fmt.Println("Для запуска маячка:")
	fmt.Printf("  beacon beacon -name %s\n", nodeName)
}

// cmdRevokeBeacon отзывает сертификат маячка.
func cmdRevokeBeacon(dataDir, serialHex string) {
	// Парсим hex serial hash (16 байт = 32 hex символа)
	if len(serialHex) != 32 {
		fmt.Fprintf(os.Stderr, "serial hash должен быть 32 hex символа (16 байт), получено: %d\n", len(serialHex))
		os.Exit(1)
	}

	var serialHash [16]byte
	for i := 0; i < 16; i++ {
		b, ok := parseHexByte(serialHex[i*2], serialHex[i*2+1])
		if !ok {
			fmt.Fprintf(os.Stderr, "невалидный hex: %s\n", serialHex)
			os.Exit(1)
		}
		serialHash[i] = b
	}

	if err := RevokeCertificate(dataDir, serialHash, 1); err != nil {
		fmt.Fprintf(os.Stderr, "ошибка отзыва: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Сертификат %X отозван.\n", serialHash)
	fmt.Println("CRL обновлён. Маячки получат обновление через gossip-протокол.")
}

// cmdListTrusted выводит список доверенных узлов.
func cmdListTrusted(dataDir string) {
	crlPath := dataDir + "/ca/crl.pem"
	certPath := dataDir + "/ca/ca-cert.pem"

	fmt.Println("=== Trust Store ===")

	caCert, err := LoadCACert(certPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "загрузка CA: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("CA: %s (CN=%s)\n", certPath, caCert.Subject.CommonName)
	fmt.Printf("    Валиден до: %s\n", caCert.NotAfter.Format("2006-01-02"))

	// Загружаем CRL
	ts, err := NewTrustStore(certPath, crlPath)
	if err != nil {
		fmt.Printf("CRL: не загружен (%v)\n", err)
	} else {
		entries := ts.GetRevokedEntries()
		fmt.Printf("CRL: версия %d, отозвано %d сертификатов\n", ts.CRLVersion(), len(entries))
		for _, entry := range entries {
			fmt.Printf("  - %X (причина: %d)\n", entry.SerialHash, entry.Reason)
		}
	}
}

// cmdImportCA импортирует CA-сертификат из внешнего файла.
func cmdImportCA(dataDir, caCertPath string) {
	if err := ImportCACert(dataDir, caCertPath); err != nil {
		fmt.Fprintf(os.Stderr, "ошибка импорта: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("CA-сертификат импортирован в %s/ca/ca-cert.pem\n", dataDir)
}

// cmdBeacon запускает Маячок.
func cmdBeacon(args []string) {
	fs := flag.NewFlagSet("beacon", flag.ExitOnError)

	cfg := DefaultConfig()

	fs.StringVar(&cfg.DataDir, "dir", cfg.DataDir, "директория с данными")
	fs.StringVar(&cfg.NodeName, "name", "", "имя этого маячка (обязательно)")
	fs.StringVar(&cfg.BindAddr, "bind", cfg.BindAddr, "адрес привязки")
	fs.StringVar(&cfg.BroadcastAddr, "broadcast", cfg.BroadcastAddr, "broadcast-адрес")
	fs.IntVar(&cfg.DiscoveryPort, "disc-port", cfg.DiscoveryPort, "UDP-порт обнаружения")
	fs.IntVar(&cfg.TLSPort, "tls-port", cfg.TLSPort, "TCP-порт TLS")
	fs.Float64Var(&cfg.RateLimitRate, "rate-limit", cfg.RateLimitRate, "макс. пакетов/сек от одного IP")
	fs.IntVar(&cfg.RateLimitBurst, "rate-burst", cfg.RateLimitBurst, "макс. burst пакетов")
	fs.IntVar(&cfg.SSHPort, "ssh-port", cfg.SSHPort, "TCP-порт SSH-сервера")
	fs.IntVar(&cfg.SSHMaxConns, "ssh-max-conns", cfg.SSHMaxConns, "макс. SSH-подключений")
	var idleTimeout time.Duration
	fs.DurationVar(&idleTimeout, "ssh-idle-timeout", cfg.SSHIdleTimeout, "idle timeout SSH")

	fs.Parse(args)

	if idleTimeout > 0 {
		cfg.SSHIdleTimeout = idleTimeout
	}

	if cfg.NodeName == "" {
		fmt.Fprintln(os.Stderr, "укажите имя маячка: beacon beacon -name <имя>")
		os.Exit(1)
	}

	// Логируем конфигурацию
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Printf("[Main] запуск маячка '%s' (discovery: %s:%d, tls: %s:%d, ssh: %s:%d)",
		cfg.NodeName, cfg.BroadcastAddr, cfg.DiscoveryPort,
		cfg.BindAddr, cfg.TLSPort, cfg.BindAddr, cfg.SSHPort)

	// Создаём и запускаем узел
	node, err := NewBeaconNode(cfg)
	if err != nil {
		log.Fatalf("[Main] ошибка инициализации: %v", err)
	}

	if err := node.Start(); err != nil {
		log.Fatalf("[Main] ошибка запуска: %v", err)
	}

	// Ждём сигнала завершения
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	log.Printf("[Main] получен сигнал %v, завершение...", sig)

	node.Stop()
	log.Println("[Main] маячок остановлен")
}

// parseHexByte парсит один hex-байт из двух символов.
func parseHexByte(hi, lo byte) (byte, bool) {
	decode := func(b byte) (byte, bool) {
		switch {
		case b >= '0' && b <= '9':
			return b - '0', true
		case b >= 'a' && b <= 'f':
			return b - 'a' + 10, true
		case b >= 'A' && b <= 'F':
			return b - 'A' + 10, true
		default:
			return 0, false
		}
	}

	hiByte, ok := decode(hi)
	if !ok {
		return 0, false
	}
	loByte, ok := decode(lo)
	if !ok {
		return 0, false
	}

	return hiByte<<4 | loByte, true
}
