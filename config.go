package main

import (
	"path/filepath"
	"time"
)

const (
	// Версия протокола обнаружения — меняется при несовместимых изменениях формата пакетов
	//
	// Версия 2: announce/echo несут публичный ключ Ed25519 отправителя, чтобы
	// сосед мог проверить подпись пакета, имея только сертификат узла. Узлы
	// версии 1 не умеют этого и отбрасываются.
	ProtocolVersion uint8 = 2

	// Магические байты в заголовке UDP-пакета ("BECN")
	DiscoveryMagic = 0x4245434E

	// Порт по умолчанию для UDP-обнаружения
	DefaultDiscoveryPort = 1984

	// Порт по умолчанию для TLS-соединений
	DefaultTLSPort = 1985

	// Интервал отправки broadcast-пакетов обнаружения
	DefaultBroadcastInterval = 5 * time.Second

	// Тайм-аут ожидания ответа при установке TLS-соединения
	DefaultDialTimeout = 10 * time.Second

	// Максимальный размер UDP-пакета (байт)
	MaxPacketSize = 1024

	// Время жизни TLS-сертификата маячка по умолчанию
	DefaultCertTTL = 90 * 24 * time.Hour // 90 дней

	// Время жизни корневого сертификата CA
	DefaultCALifetime = 10 * 365 * 24 * time.Hour // 10 лет

	// ed25519KeyFile — имя файла приватного Ed25519-ключа в директории узла.
	// Публичная часть ключа хранится в сертификате (SAN URI), поэтому на диске
	// лежит только приватная половина.
	ed25519KeyFile = "ed25519-key.pem"

	// Интервал проверки CRL и обновления Trust Store
	DefaultCRLCheckInterval = 1 * time.Hour

	// Максимальный размер CRL, который мы принимаем по gossip (1 МБ)
	MaxCRLSize = 1 << 20
)

// Типы discovery-пакетов
const (
	PktAnnounce uint8 = 0x01 // Маячок объявляет о себе
	PktEcho     uint8 = 0x02 // Ответ на announce (подтверждение присутствия)
	PktGossip   uint8 = 0x03 // Передача обновлений CRL
	// PktCertShare передаёт свой сертификат соседу по уже установленному
	// mTLS. Без него узлы не знают сертификатов друг друга и не могут ни
	// разрешить имя в адрес, ни принять SSH, ни проверить подпись gossip.
	PktCertShare uint8 = 0x04
)

// Config содержит все параметры конфигурации запуска.
// Заполняется из флагов CLI или значений по умолчанию.
type Config struct {
	// Режим работы: "ca" — Главная Нода, "beacon" — Маячок
	Mode string

	// Путь к директории с данными (ключи, сертификаты, конфиг)
	DataDir string

	// --- Параметры CA (Главной Ноды) ---
	CAKeyPath  string // Путь к приватному ключу CA
	CACertPath string // Путь к сертификату CA
	CRLPath    string // Путь к списку отозванных сертификатов

	// --- Параметры Маячка ---
	NodeName       string   // Уникальное имя этого маячка (используется как CN в сертификате)
	NodeID         [16]byte // Уникальный идентификатор узла (UUID-like)
	TLSKeyPath     string   // Путь к приватному ключу маячка
	TLSCertPath    string   // Путь к сертификату маячка
	TrustedCAPath  string   // Путь к корневому сертификату CA для проверки пиров
	TrustStorePath string   // Путь к локальному Trust Store (список известных пиров)

	// --- Сетевые параметры ---
	DiscoveryPort int    // UDP-порт для обнаружения
	TLSPort       int    // TCP-порт для TLS-соединений
	BroadcastAddr string // Адрес для UDP broadcast (например "255.255.255.255" или конкретная подсеть)
	BindAddr      string // Адрес привязки для TCP-слушателей (TLS, SSH)

	// DiscoveryBindAddr — адрес привязки UDP-слушателя discovery.
	//
	// Отдельное поле не для удобства, а по необходимости: broadcast-пакет
	// доставляется только сокетам, слушающим все адреса, поэтому значение
	// BindAddr (например -bind 192.168.1.166) для discovery не годится.
	// Пусто = слушать 0.0.0.0, что и требуется в обычном случае.
	DiscoveryBindAddr string

	CertTTL time.Duration // Время жизни выдаваемых сертификатов

	// --- Параметры безопасности ---
	RateLimitBurst  int     // Максимум пакетов в секунду от одного IP
	RateLimitRate   float64 // Средняя скорость (пакетов/сек)
	MaxConnsPerPeer int     // Максимум одновременных TLS-соединений с одним пиром

	// --- Параметры SSH-сервера ---
	// SSH выключен по умолчанию: включение открывает shell пользователю,
	// от имени которого работает маячок (обычно root), любому узлу сети с
	// валидным сертификатом. Решение об этом должно приниматься явно.
	SSHEnabled       bool          // Включить SSH-сервер (флаг -ssh)
	SSHPort          int           // TCP-порт SSH-сервера
	SSHMaxConns      int           // Максимум одновременных SSH-подключений
	SSHIdleTimeout   time.Duration // Тайм-аут неактивности для SSH
	SSHShell         string        // Интерпретатор для сессий (по умолчанию /bin/sh)
	SSHAllowCNs      []string      // Разрешённые CN (пустой список при -ssh = отказ всем)
	SSHAllowCommands []string      // Разрешённые exec-команды (пустой = любой exec)
	SSHInteractive   bool          // Разрешить интерактивный shell

	// --- Provisioning ---
	ProvisionToken string // Токен для offline-provisioning нового маячка
	ProvisionName  string // Имя нового маячка для выдачи сертификата
}

// DefaultConfig возвращает конфигурацию с параметрами по умолчанию.
func DefaultConfig() *Config {
	return &Config{
		DataDir:         "./beacon-data",
		DiscoveryPort:   DefaultDiscoveryPort,
		TLSPort:         DefaultTLSPort,
		BroadcastAddr:   "255.255.255.255",
		BindAddr:        "0.0.0.0",
		CertTTL:         DefaultCertTTL,
		RateLimitBurst:  10,
		RateLimitRate:   2.0,
		MaxConnsPerPeer: 5,
		SSHPort:         2222,
		SSHMaxConns:     10,
		SSHIdleTimeout:  10 * time.Minute,
		// Shell по умолчанию — /bin/sh: bash не обязан существовать
		// (например на mipsle-роутерах под OpenWrt).
		SSHShell: "/bin/sh",
		// Интерактивный shell разрешён: он всё ещё требует -ssh и непустого
		// -ssh-allow, поэтому отказ по умолчанию здесь ослабил бы безопасность
		// только при явно включённом SSH.
		SSHInteractive: true,
	}
}

// CAPaths возвращает пути к файлам CA в директории данных.
func (c *Config) CAPaths() (keyPath, certPath, crlPath string) {
	keyPath = c.DataDir + "/ca/ca-key.pem"
	certPath = c.DataDir + "/ca/ca-cert.pem"
	crlPath = c.DataDir + "/ca/crl.pem"
	if c.CAKeyPath != "" {
		keyPath = c.CAKeyPath
	}
	if c.CACertPath != "" {
		certPath = c.CACertPath
	}
	if c.CRLPath != "" {
		crlPath = c.CRLPath
	}
	return
}

// Ed25519KeyPath возвращает путь к приватному Ed25519-ключу этого маячка.
func (c *Config) Ed25519KeyPath() string {
	return filepath.Join(c.DataDir, c.NodeName, ed25519KeyFile)
}

// BeaconPaths возвращает пути к файлам этого маячка.
func (c *Config) BeaconPaths() (keyPath, certPath, trustedCAPath string) {
	keyPath = c.DataDir + "/" + c.NodeName + "/key.pem"
	certPath = c.DataDir + "/" + c.NodeName + "/cert.pem"
	trustedCAPath = c.DataDir + "/ca/ca-cert.pem"
	if c.TLSKeyPath != "" {
		keyPath = c.TLSKeyPath
	}
	if c.TLSCertPath != "" {
		certPath = c.TLSCertPath
	}
	if c.TrustedCAPath != "" {
		trustedCAPath = c.TrustedCAPath
	}
	return
}
