package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
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
	case "monitor":
		cmdMonitor(os.Args[2:])
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
  beacon monitor            — TUI-монитор состояния сети

Команды CA:
  generate-ca              — генерация корневого CA
  provision-beacon <имя>   — выдача сертификата новому маячку
  revoke-beacon <serial>   — отзыв сертификата маячка
  list-trusted             — список доверенных узлов
  import-ca <путь>         — импорт CA-сертификата из файла
  export-ca                — экспорт CA-файлов для копирования
  sync-crl <host:path>     — синхронизация CRL с другой CA

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

	// Загружаем TrustStore для проверки хост-ключей
	_, _, caPath := cfg.BeaconPaths()
	crlPath := cfg.DataDir + "/ca/crl.pem"
	if _, err := os.Stat(caPath); err == nil {
		ts, err := NewTrustStore(caPath, crlPath)
		if err == nil {
			ts.RegisterEd25519KeyFromDisk(cfg.DataDir)
			client.SetTrustStore(ts)
		}
	}

	if err := client.Connect(target, execCmd); err != nil {
		fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
		os.Exit(1)
	}
}

// cmdMonitor запускает TUI-монитор состояния сети.
func cmdMonitor(args []string) {
	fs := flag.NewFlagSet("monitor", flag.ExitOnError)
	dataDir := fs.String("dir", "./beacon-data", "директория с данными")
	nodeName := fs.String("name", "", "имя этого маячка (обязательно)")

	fs.Parse(args)

	if *nodeName == "" {
		fmt.Fprintln(os.Stderr, "укажите имя: beacon monitor -name <имя>")
		os.Exit(1)
	}

	cfg := DefaultConfig()
	cfg.DataDir = *dataDir
	cfg.NodeName = *nodeName

	if err := RunMonitor(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ошибка монитора: %v\n", err)
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
	reissue := fs.Bool("reissue", false, "пере-выдача для существующего узла (потерян ключ)")
	serialArg := fs.String("serial", "", "серийный номер сертификата (для revoke-beacon)")

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
		cmdProvisionBeacon(*dataDir, *caKeyPath, *caCertPath, nodeName, *reissue)

	case "revoke-beacon":
		if fs.NArg() < 1 && *serialArg == "" {
			fmt.Fprintln(os.Stderr, "укажите серийный номер: beacon ca revoke-beacon -serial <номер>")
			os.Exit(1)
		}
		// Приоритет у флага: значение копипастом из list-trusted.
		// Позиционный аргумент оставлен для обратной совместимости.
		target := *serialArg
		if target == "" {
			target = fs.Arg(0)
		}
		cmdRevokeBeacon(*dataDir, target)

	case "list-trusted":
		cmdListTrusted(*dataDir)

	case "import-ca":
		if fs.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "укажите путь к CA-сертификату: beacon ca import-ca <путь>")
			os.Exit(1)
		}
		cmdImportCA(*dataDir, fs.Arg(0))

	case "export-ca":
		cmdExportCA(*dataDir)

	case "sync-crl":
		if fs.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "укажите источник CRL: beacon ca sync-crl <host:path>")
			os.Exit(1)
		}
		cmdSyncCRL(*dataDir, fs.Arg(0))

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

// normalizeNodeName проверяет и нормализует имя узла (CN).
//
// Префикс beacon- добавляется автоматически, но проверка длины идёт ДО
// добавления: иначе опечатка из двух символов молча превратилась бы в
// валидное имя beacon-xx, и пользователь не заметил бы промаха.
func normalizeNodeName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)

	if trimmed == "" {
		return "", fmt.Errorf("имя узла не может быть пустым")
	}

	// Минимум проверяем по исходному имени, до добавления префикса: иначе
	// опечатка из двух символов молча превратилась бы в валидное "beacon-xx",
	// и пользователь не заметил бы промаха.
	if len(trimmed) < 3 {
		return "", fmt.Errorf("имя должно быть не короче 3 символов (получено %d)", len(trimmed))
	}

	if len(trimmed) > 63 {
		return "", fmt.Errorf("имя должно быть не длиннее 63 символов (получено %d)", len(trimmed))
	}

	if !strings.HasPrefix(trimmed, "beacon-") {
		if len(trimmed)+len("beacon-") > 63 {
			return "", fmt.Errorf("имя с префиксом beacon- превысит 63 символа (получено %d)", len(trimmed))
		}
		trimmed = "beacon-" + trimmed
	}

	return trimmed, nil
}

// cmdProvisionBeacon выдаёт сертификат новому маячку.
//
// Обычный вызов — только для новых имён: если CN уже есть в индексе CA,
// команда отказывает и предлагает -reissue. Это защищает от ситуации, когда
// опечатка или потерянный ключ молча выдают второй сертификат на то же имя:
// в сети появляются два узла с одинаковым CN, и отзыв одного задевает оба.
//
// -reissue — пере-выдача для существующего имени (устройство потеряло ключ).
// Старый сертификат при этом НЕ отзывается автоматически: он остаётся валидным
// до конца TTL, и пользователю выводится его серийный номер для ручного отзыва.
func cmdProvisionBeacon(dataDir, caKeyPath, caCertPath, nodeName string, reissue bool) {
	if reissue {
		fmt.Printf("Пере-выдача сертификата для маячка: %s\n", nodeName)
	} else {
		fmt.Printf("Выдача сертификата для маячка: %s\n", nodeName)
	}

	nodeName, err := normalizeNodeName(nodeName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	idx, err := LoadCAIndex(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "чтение индекса CA: %v\n", err)
		os.Exit(1)
	}

	existing, exists := idx.Lookup(nodeName)

	if exists && !reissue {
		fmt.Fprintf(os.Stderr, "сертификат для %s уже выдан %s\n", nodeName, existing.IssuedAt)
		fmt.Fprintf(os.Stderr, "серийный номер: %s\n", existing.Serial)
		fmt.Fprintln(os.Stderr, "\nЕсли устройство потеряло ключ, пере-выпустите сертификат:")
		fmt.Fprintf(os.Stderr, "  beacon ca provision-beacon -reissue -dir %s %s\n", dataDir, nodeName)
		os.Exit(1)
	}

	if !exists && reissue {
		fmt.Fprintf(os.Stderr, "сертификат для %s не найден в индексе CA\n", nodeName)
		fmt.Fprintln(os.Stderr, "возможно, имя указано с ошибкой. Доступные узлы:")
		for _, name := range idx.Names() {
			fmt.Fprintf(os.Stderr, "  - %s\n", name)
		}
		os.Exit(1)
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

	// Архивируем прежний сертификат: пере-выдача перезапишет cert.pem, а его
	// серийник мы сейчас покажем пользователю для отзыва — искать его потом
	// будет негде.
	if exists {
		if err := ArchiveCertIfPresent(dataDir, nodeName); err != nil {
			fmt.Fprintf(os.Stderr, "архивирование прежнего сертификата: %v\n", err)
			fmt.Fprintln(os.Stderr, "выдача прервана, чтобы не потерять сертификат для отзыва")
			os.Exit(1)
		}
	}

	issued, err := IssueCertificate(caKey, caCertData, dataDir, nodeName, DefaultCertTTL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка выдачи сертификата: %v\n", err)
		os.Exit(1)
	}

	idx.Nodes[nodeName] = NewEntry(issued.Serial, issued.NodeID)
	if err := SaveCAIndex(dataDir, idx); err != nil {
		fmt.Fprintf(os.Stderr, "сохранение индекса CA: %v\n", err)
		fmt.Fprintln(os.Stderr, "сертификат выпущен, но индекс не обновлён — повторите выдачу")
		os.Exit(1)
	}

	fmt.Println("Сертификат успешно выдан:")
	fmt.Printf("  Node ID:      %X\n", issued.NodeID)
	fmt.Printf("  Серийный:     %s\n", issued.Serial)
	fmt.Printf("  Сертификат:   %s\n", issued.CertPath)
	fmt.Printf("  Ключ TLS:     %s (права 0600)\n", issued.KeyPath)
	fmt.Printf("  Ключ Ed25519: %s (права 0600)\n", issued.Ed25519Path)

	if exists {
		fmt.Println()
		fmt.Println("ВНИМАНИЕ: это пере-выдача. Старый сертификат всё ещё валиден,")
		fmt.Printf("  его серийный номер: %s\n", existing.Serial)
		fmt.Println("В сети будут два сертификата с одинаковым CN. Отзовите старый:")
		fmt.Printf("  beacon ca revoke-beacon -serial %s\n", existing.Serial)
	}

	fmt.Println()
	fmt.Println("Для запуска маячка:")
	fmt.Printf("  beacon beacon -name %s\n", nodeName)
}

// cmdRevokeBeacon отзывает сертификат маячка.
//
// Принимает серийный номер сертификата — десятичную строку из
// `ca list-trusted`. Это и есть ключ отзыва: уникальный на каждую выдачу,
// поэтому отзыв пере-выданного сертификата не задевает свежий.
func cmdRevokeBeacon(dataDir, serialArg string) {
	serial, ok := new(big.Int).SetString(strings.TrimSpace(serialArg), 10)
	if !ok {
		fmt.Fprintf(os.Stderr, "'%s' не является серийным номером сертификата\n", serialArg)
		fmt.Fprintln(os.Stderr, "номер выводит команда 'beacon ca list-trusted'")
		os.Exit(1)
	}

	// Показываем, кому принадлежит сертификат: отзыв по номеру вслепую —
	// плохая идея.
	if cert, err := findCertBySerial(dataDir, serial); err == nil {
		fmt.Printf("Отзыв сертификата CN=%s\n", cert.Subject.CommonName)
		if !cert.NotAfter.IsZero() {
			fmt.Printf("  действует до: %s\n", cert.NotAfter.Format("2006-01-02"))
		}
	} else {
		fmt.Fprintf(os.Stderr, "сертификат %s не найден на диске: %v\n", serial, err)
		fmt.Fprintln(os.Stderr, "продолжаю отзыв по номеру — проверьте номер по 'ca list-trusted'")
	}

	if err := RevokeCertificate(dataDir, serial, 1); err != nil {
		fmt.Fprintf(os.Stderr, "ошибка отзыва: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Сертификат %s отозван. CRL подписан ключом CA и обновлён.\n", serial)
	fmt.Println("Маячки получат обновление через gossip-протокол.")
}

// findCertBySerial ищет выпущенный сертификат по серийному номеру.
//
// Сначала сканируются живые каталоги узлов, затем архив заменённых
// (ca/replaced/) — туда попадают сертификаты, вытесненные пере-выдачей.
// Без архива старый сертификат пере-выданного узла было бы негде искать.
func findCertBySerial(dataDir string, serial *big.Int) (*x509.Certificate, error) {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return nil, fmt.Errorf("чтение каталога данных: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "ca" || entry.Name() == "peers" {
			continue
		}

		certPath := filepath.Join(dataDir, entry.Name(), "cert.pem")
		certData, err := os.ReadFile(certPath)
		if err != nil {
			continue
		}

		block, _ := pem.Decode(certData)
		if block == nil {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		if cert.SerialNumber.Cmp(serial) == 0 {
			return cert, nil
		}
	}

	// Не нашли среди живых — ищем в архиве заменённых сертификатов.
	cert, err := findCertBySerialInArchive(dataDir, serial)
	if err == nil {
		return cert, nil
	}

	return nil, fmt.Errorf("сертификат с серийным номером %s не найден — "+
		"проверьте номер по 'beacon ca list-trusted -dir %s'", serial, dataDir)
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

	// Выданные узлы с серийными номерами: именно эти номера нужны для
	// revoke-beacon, раньше их было негде взять.
	idx, err := LoadCAIndex(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "чтение индекса CA: %v\n", err)
		os.Exit(1)
	}

	ts, err := NewTrustStore(certPath, crlPath)
	if err != nil {
		fmt.Printf("CRL: не загружен (%v)\n", err)
	}

	if len(idx.Nodes) == 0 {
		fmt.Println("\nУзлы не выданы (пустой индекс CA).")
	} else {
		fmt.Println()
		fmt.Printf("%-20s %-34s %-8s %s\n", "ИМЯ", "NODE ID", "СТАТУС", "СЕРИЙНЫЙ НОМЕР")
		fmt.Println(strings.Repeat("-", 100))

		for _, cn := range idx.Names() {
			entry := idx.Nodes[cn]

			status := "ACTIVE"
			if ts != nil {
				serial, err := entry.SerialNumber()
				if err == nil && ts.IsRevokedBySerial(serial) {
					status = "REVOKED"
				}
			}

			fmt.Printf("%-20s %-34s %-8s %s\n", cn, entry.NodeID, status, entry.Serial)
		}
	}

	if ts == nil {
		return
	}

	entries := ts.GetRevokedEntries()
	fmt.Printf("\nCRL: номер %d, отозвано %d сертификатов\n", ts.CRLVersion(), len(entries))
	for _, entry := range entries {
		fmt.Printf("  - %s (причина: %d, отозван: %s)\n",
			entry.SerialNumber, entry.Reason, entry.RevokedAt.Format("2006-01-02"))
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

// cmdExportCA экспортирует CA-файлы для копирования на другую машину.
func cmdExportCA(dataDir string) {
	fmt.Println("=== CA Export ===")
	fmt.Printf("Директория: %s/ca/\n", dataDir)
	fmt.Println()
	fmt.Println("Файлы для копирования на другую CA-машину:")
	fmt.Println("  1. ca-key.pem     — приватный ключ CA (СЕКРЕТНО!)")
	fmt.Println("  2. ca-cert.pem    — сертификат CA (публичный)")
	fmt.Println("  3. crl.pem        — список отозванных сертификатов")
	fmt.Println()
	fmt.Println("Пример копирования:")
	fmt.Printf("  scp %s/ca/*.pem user@remote-host:~/beacon-data/ca/\n", dataDir)
	fmt.Println()
	fmt.Println("После копирования на удалённой машине запустите:")
	fmt.Println("  beacon ca list-trusted — проверьте что CA загружен")
}

// cmdSyncCRL синхронизирует CRL с другой CA-машиной через scp.
func cmdSyncCRL(dataDir, source string) {
	// source формат: user@host:/path/to/crl.pem
	fmt.Printf("Синхронизация CRL с %s...\n", source)

	crlPath := dataDir + "/ca/crl.pem"

	// Пытаемся скопировать CRL через scp
	cmd := fmt.Sprintf("scp %s %s", source, crlPath)
	fmt.Printf("Выполняю: %s\n", cmd)

	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка scp: %v\n%s", err, string(out))
		os.Exit(1)
	}

	fmt.Println("CRL успешно синхронизирован")
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
