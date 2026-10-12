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
	// Порт discovery должен совпадать с тем, на котором слушают маячки:
	// иначе broadcast-запрос уйдёт мимо, и имя не разрешится в адрес.
	discPort := fs.Int("disc-port", DefaultDiscoveryPort, "UDP-порт discovery (как у маячков)")
	broadcastAddr := fs.String("broadcast", "255.255.255.255", "broadcast-адрес сети")

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
	cfg.DiscoveryPort = *discPort
	cfg.BroadcastAddr = *broadcastAddr
	if *sshPort > 0 {
		cfg.SSHPort = *sshPort
	}

	if cfg.NodeName == "" {
		fmt.Fprintln(os.Stderr, "укажите имя этого маячка: beacon ssh -name <имя> <цель> [команда]")
		os.Exit(1)
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

	// Порт, по которому пингуются соседи. Без этого флага монитор стучался бы
	// в 1985, даже когда маячок запущен на другом порту, и показывал соседей
	// офлайн при живом узле.
	tlsPort := fs.Int("tls-port", DefaultTLSPort, "TCP-порт маячков для проверки доступности")

	fs.Parse(args)

	if *nodeName == "" {
		fmt.Fprintln(os.Stderr, "укажите имя: beacon monitor -name <имя>")
		os.Exit(1)
	}

	cfg := DefaultConfig()
	cfg.DataDir = *dataDir
	cfg.NodeName = *nodeName
	cfg.TLSPort = *tlsPort

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
	nodeName := fs.String("node", "", "имя узла (для revoke-beacon)")
	role := fs.String("role", "peer", "роль сертификата: peer (участие в сети) или server (плюс SSH)")

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
		cmdProvisionBeacon(*dataDir, *caKeyPath, *caCertPath, nodeName, *reissue, *role)

	case "revoke-beacon":
		if fs.NArg() < 1 && *serialArg == "" && *nodeName == "" {
			fmt.Fprintln(os.Stderr, "укажите, что отзывать: -serial <номер> или -node <CN>")
			os.Exit(1)
		}
		if *nodeName != "" {
			cmdRevokeBeaconByNode(*dataDir, *nodeName)
			return
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
func cmdProvisionBeacon(dataDir, caKeyPath, caCertPath, nodeName string, reissue bool, roleName string) {
	role, err := ParseRole(roleName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if reissue {
		fmt.Printf("Пере-выдача сертификата для маячка: %s\n", nodeName)
	} else {
		fmt.Printf("Выдача сертификата для маячка: %s\n", nodeName)
	}

	normalized, err := normalizeNodeName(nodeName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	nodeName = normalized

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

	issued, err := IssueCertificate(caKey, caCertData, dataDir, nodeName, DefaultCertTTL, role)
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
	fmt.Printf("  Роль:        %s\n", role)
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

// cmdRevokeBeaconByNode отзывает сертификат по имени узла.
//
// Удобнее, чем вводить серийник руками: имя берётся из индекса CA, а
// соответствующий сертификат ищется на диске (включая архив пере-выданных).
func cmdRevokeBeaconByNode(dataDir, cn string) {
	normalized, err := normalizeNodeName(cn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	idx, err := LoadCAIndex(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "чтение индекса CA: %v\n", err)
		os.Exit(1)
	}

	entry, ok := idx.Lookup(normalized)
	if !ok {
		fmt.Fprintf(os.Stderr, "узел %s не найден в индексе CA\n", normalized)
		fmt.Fprintln(os.Stderr, "доступные узлы:")
		for _, name := range idx.Names() {
			fmt.Fprintf(os.Stderr, "  - %s\n", name)
		}
		os.Exit(1)
	}

	fmt.Printf("Отзыв узла %s\n", normalized)
	cmdRevokeBeacon(dataDir, entry.Serial)
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

// cmdExportCA объясняет, что и зачем копировать на вторую CA-машину.
//
// Раньше команда предлагала скопировать ca-key.pem вместе с сертификатом и
// CRL. Это антипаттерн: две машины с одним приватным ключом CA означают, что
// компрометация любой из них компрометирует всю PKI. Для работы «двумя CA»
// достаточно копировать публичные файлы, а второй CA должен выпускать
// сертификаты СВОИМ ключом и получать доверие через import-ca.
func cmdExportCA(dataDir string) {
	fmt.Println("=== CA Export ===")
	fmt.Printf("Директория: %s/ca/\n", dataDir)
	fmt.Println()
	fmt.Println("ПУБЛИЧНЫЕ файлы (их и копируйте):")
	fmt.Println("  1. ca-cert.pem    — сертификат CA")
	fmt.Println("  2. crl.pem        — список отозванных сертификатов")
	fmt.Println()
	fmt.Println("СЕКРЕТНО и НЕ ПОДЛЕЖИТ копированию:")
	fmt.Println("  ca-key.pem        — приватный ключ CA")
	fmt.Println()
	fmt.Println("Раздача приватного ключа между машинами означает, что")
	fmt.Println("компрометация любой из них компрометирует всю сеть.")
	fmt.Println()
	fmt.Println("Если на второй машине должен работать полноценный CA, он")
	fmt.Println("генерирует СВОЙ ключ, а все маячки импортируют оба сертификата:")
	fmt.Printf("  beacon ca import-ca -dir %s /путь/до/ca-cert.pem\n", dataDir)
	fmt.Println()
	fmt.Println("Если вторая машина нужна только для чтения CRL:")
	fmt.Printf("  beacon ca list-trusted -dir %s\n", dataDir)
}

// cmdSyncCRL синхронизирует CRL с другой CA-машиной через scp.
//
// Источник строго валидируется: раньше строка подставлялась в sh -c, то есть
// `beacon ca sync-crl 'x; rm -rf /'` выполнял обычную инъекцию. scp теперь
// запускается без оболочки, а формат ограничен user@host:/path.
func cmdSyncCRL(dataDir, source string) {
	user, host, path, err := parseSCPSource(source)
	if err != nil {
		fmt.Fprintf(os.Stderr, "некорректный источник: %v\n", err)
		os.Exit(1)
	}

	crlPath := dataDir + "/ca/crl.pem"

	// Без sh -c: аргументы передаются напрямую, поэтому спецсимволы
	// в пути или имени хоста не выполняются.
	cmd := exec.Command("scp", user+"@"+host+":"+path, crlPath)
	cmd.Stderr = os.Stderr

	fmt.Printf("Синхронизация CRL с %s@%s:%s\n", user, host, path)

	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "scp завершился ошибкой: %v\n%s", err, out)
		os.Exit(1)
	}

	fmt.Println("CRL синхронизирован. Проверьте список отозванных:")
	fmt.Printf("  beacon ca list-trusted -dir %s\n", dataDir)
}

// parseSCPSource разбирает источник вида user@host:/path.
//
// Разделитель ":" встречается ровно один раз: иначе user@host:2222:path
// разобрался бы как кривой путь и молча ушёл бы в scp другой командой.
func parseSCPSource(source string) (user, host, path string, err error) {
	source = strings.TrimSpace(source)

	if source == "" {
		return "", "", "", fmt.Errorf("источник не задан (ожидается user@host:/path/to/crl.pem)")
	}

	if strings.ContainsAny(source, " \t\n;|&$`<>") {
		return "", "", "", fmt.Errorf("источник содержит недопустимые символы: %q", source)
	}

	// Разделяем на [user@host] и [path]
	colon := strings.LastIndex(source, ":")
	if colon <= 0 || colon == len(source)-1 {
		return "", "", "", fmt.Errorf("ожидается формат user@host:/путь/до/crl.pem, получено %q", source)
	}

	remote := source[:colon]
	path = source[colon+1:]

	at := strings.Index(remote, "@")
	if at <= 0 || at == len(remote)-1 {
		return "", "", "", fmt.Errorf("ожидается формат user@host:/путь/до/crl.pem, получено %q", source)
	}

	user = remote[:at]
	host = remote[at+1:]

	if user == "" || host == "" || path == "" {
		return "", "", "", fmt.Errorf("пустой user, host или path в %q", source)
	}

	return user, host, path, nil
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

	// SSH включён только при -ssh. По умолчанию маячок отдаёт shell
	// пользователю, от имени которого запущен (часто root), любому узлу
	// с валидным сертификатом — поэтому это выбор владельца, а не дефолт.
	sshEnabled := fs.Bool("ssh", false, "включить SSH-сервер на этом узле")
	tuiEnabled := fs.Bool("tui", false, "показать TUI-монитор в этом же процессе")
	sshAllow := fs.String("ssh-allow", "", "CN, которым разрешён вход (через запятую)")
	sshAllowCommands := fs.String("ssh-allow-commands", "", "разрешённые exec-команды (через запятую)")
	sshShell := fs.String("ssh-shell", cfg.SSHShell, "интерпретатор для SSH-сессий")

	fs.Parse(args)

	if idleTimeout > 0 {
		cfg.SSHIdleTimeout = idleTimeout
	}

	// SSH-политика из флагов.
	cfg.SSHEnabled = *sshEnabled
	cfg.SSHAllowCNs = splitAndTrim(*sshAllow)
	cfg.SSHAllowCommands = splitAndTrim(*sshAllowCommands)
	cfg.SSHShell = *sshShell

	if cfg.NodeName == "" {
		fmt.Fprintln(os.Stderr, "укажите имя маячка: beacon beacon -name <имя>")
		os.Exit(1)
	}

	if cfg.SSHEnabled && len(cfg.SSHAllowCNs) == 0 {
		log.Printf("[SSH] включён, но -ssh-allow пуст: вход разрешён только узлу с "+
			"CN=%s. Добавьте -ssh-allow beacon-<имя>, чтобы пускать других", cfg.NodeName)
	}

	// Логируем конфигурацию
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Printf("[Main] запуск маячка '%s' (discovery: %s:%d, tls: %s:%d, ssh: %s)",
		cfg.NodeName, cfg.BroadcastAddr, cfg.DiscoveryPort,
		cfg.BindAddr, cfg.TLSPort, sshState(cfg))

	// Создаём и запускаем узел
	node, err := NewBeaconNode(cfg)
	if err != nil {
		log.Fatalf("[Main] ошибка инициализации: %v", err)
	}

	if err := node.Start(); err != nil {
		log.Fatalf("[Main] ошибка запуска: %v", err)
	}

	// state.json нужен отдельному процессу `beacon monitor`, поэтому он пишется
	// всегда, а не только в режиме -tui. Файл маленький, обновляется раз в
	// секунду и содержит только имена и адреса пиров.
	if err := node.StartStateWriter(); err != nil {
		log.Printf("[Main] запись состояния не запущена: %v", err)
	}

	// TUI в этом же процессе видит реальных пиров из node.peers: намного
	// честнее, чем отдельный монитор, вынужденный гадать по сертификатам.
	if *tuiEnabled {
		runTUI(node)
		return
	}

	// Ждём сигнала завершения
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	log.Printf("[Main] получен сигнал %v, завершение...", sig)

	node.Stop()
	log.Println("[Main] маячок остановлен")
}

// runTUI поднимает монитор поверх уже запущенного маячка.
//
// Пиры берутся прямо из памяти маячка, а не из state.json: тот же процесс и так
// знает адреса, и файл обновлялся бы с задержкой в секунду. state.json при
// этом всё равно пишется (см. cmdBeacon) — по нему работает отдельный процесс
// `beacon monitor`.
func runTUI(node *BeaconNode) {
	// Монитор запускается в этом же процессе, но в своей горутине: TUI
	// занимает терминал, и без этого сигналы завершения не доедут.
	go func() {
		if err := runMonitor(node.config, livePeerLister(node.config, node)); err != nil {
			log.Printf("[Main] монитор завершился с ошибкой: %v", err)
		}
	}()

	// Держим процесс живым, пока монитор не закроется.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// TUI выходит по 'q' сам; здесь ловим системные сигналы.
	<-sigCh

	node.Stop()
	log.Println("[Main] маячок остановлен")
}

// splitAndTrim разбивает список через запятую, отбрасывая пустые элементы.
func splitAndTrim(s string) []string {
	var out []string

	for _, part := range strings.Split(s, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}

	return out
}

// sshState описывает состояние SSH для лога запуска.
func sshState(cfg *Config) string {
	if !cfg.SSHEnabled {
		return "выключен"
	}
	return fmt.Sprintf("%s:%d", cfg.BindAddr, cfg.SSHPort)
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
