package main

import (
	"time"
)

const (
	// Версия протокола обнаружения — меняется при несовместимых изменениях формата пакетов
	ProtocolVersion uint8 = 1

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
)

// Config содержит все параметры конфигурации запуска.
// Заполняется из флагов CLI или значений по умолчанию.
type Config struct {
	// Режим работы: "ca" — Главная Нода, "beacon" — Маячок
	Mode string

	// Путь к директории с данными (ключи, сертификаты, конфиг)
	DataDir string

	// --- Параметры CA (Главной Ноды) ---
	CAKeyPath    string // Путь к приватному ключу CA
	CACertPath   string // Путь к сертификату CA
	CRLPath      string // Путь к списку отозванных сертификатов

	// --- Параметры Маячка ---
	NodeName       string // Уникальное имя этого маячка (используется как CN в сертификате)
	NodeID         [16]byte // Уникальный идентификатор узла (UUID-like)
	TLSKeyPath     string // Путь к приватному ключу маячка
	TLSCertPath    string // Путь к сертификату маячка
	TrustedCAPath  string // Путь к корневому сертификату CA для проверки пиров
	TrustStorePath string // Путь к локальному Trust Store (список известных пиров)

	// --- Сетевые параметры ---
	DiscoveryPort   int    // UDP-порт для обнаружения
	TLSPort         int    // TCP-порт для TLS-соединений
	BroadcastAddr   string // Адрес для UDP broadcast (например "255.255.255.255" или конкретная подсеть)
	BindAddr        string // Адрес привязки для TCP-слушателя
	CertTTL         time.Duration // Время жизни выдаваемых сертификатов

	// --- Параметры безопасности ---
	RateLimitBurst   int     // Максимум пакетов в секунду от одного IP
	RateLimitRate    float64 // Средняя скорость (пакетов/сек)
	MaxConnsPerPeer  int     // Максимум одновременных TLS-соединений с одним пиром

	// --- Параметры SSH-сервера ---
	SSHPort        int           // TCP-порт SSH-сервера
	SSHMaxConns    int           // Максимум одновременных SSH-подключений
	SSHIdleTimeout time.Duration // Тайм-аут неактивности для SSH

	// --- Provisioning ---
	ProvisionToken  string // Токен для offline-provisioning нового маячка
	ProvisionName   string // Имя нового маячка для выдачи сертификата
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
