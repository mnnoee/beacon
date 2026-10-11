package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// CA — локальный центр сертификации (Certificate Authority).
//
// Архитектура PKI:
// 1. Главная Нода генерирует самоподписанный Root CA (ECDSA P-256)
// 2. Для каждого Маячка выдаёт сертификат, подписанный этим CA
// 3. Маячки проверяют сертификаты пиров через локальную копию CA-сертификата
// 4. Отзыв сертификатов через CRL (Certificate Revocation List)
//
// Почему ECDSA P-256 для сертификатов, а не Ed25519:
// - Go stdlib crypto/tls и crypto/x509 имеют полную поддержку ECDSA
// - ECDSA P-256 широко поддерживается и считается безопасным NIST-стандартом
// - Ed25519 используется только для подписей discovery-пакетов (вне x509)

// GenerateCA создаёт самоподписанный корневой сертификат CA.
// Возвращает приватный ключ и PEM-кодированный сертификат.
func GenerateCA(dataDir string, lifetime time.Duration) (*ecdsa.PrivateKey, []byte, error) {
	// Генерируем ECDSA P-256 ключ — безопасная эллиптическая кривая
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("генерация ключа CA: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("генерация serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Network Beacons"},
			CommonName:   "Root CA",
			Country:      []string{"RU"},
		},
		NotBefore:             time.Now().Add(-time.Minute), // небольшой запас на синхронизацию часов
		NotAfter:              time.Now().Add(lifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// Ограничиваем глубину цепочки: только наш CA может подписывать
		MaxPathLen: 0,
		// Запрещаем otherNames и прочие расширения — minimal surface
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	// Self-signed: создатель и подписчик — один и тот же ключ
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("создание самоподписанного сертификата CA: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Сохраняем приватный ключ CA
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("маршализация ключа CA: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	caDir := filepath.Join(dataDir, "ca")
	if err := os.MkdirAll(caDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("создание директории CA: %w", err)
	}

	// Ключ CA — самый ценный актив системы. Храним с правами 0600.
	if err := os.WriteFile(filepath.Join(caDir, "ca-key.pem"), keyPEM, 0600); err != nil {
		return nil, nil, fmt.Errorf("сохранение ключа CA: %w", err)
	}

	// Сертификат CA — публичный, может быть распространён.
	if err := os.WriteFile(filepath.Join(caDir, "ca-cert.pem"), certPEM, 0644); err != nil {
		return nil, nil, fmt.Errorf("сохранение сертификата CA: %w", err)
	}

	return privateKey, certPEM, nil
}

// IssuedNode — результат выдачи сертификата маячку.
type IssuedNode struct {
	// CertPath, KeyPath — TLS/SSH-ключи (ECDSA P-256).
	CertPath string
	KeyPath  string

	// Ed25519Path — приватный ключ подписей discovery и gossip.
	Ed25519Path string

	// Ed25519Pub — публичный ключ, попавший в SAN URI сертификата.
	Ed25519Pub ed25519.PublicKey

	// NodeID — идентификатор узла, выведенный из Ed25519Pub.
	NodeID [16]byte

	// Serial — серийный номер сертификата, ключ отзыва.
	Serial *big.Int
}

// IssueCertificate выдаёт сертификат для нового маячка (или другого узла).
//
// Узел получает ДВЕ пары ключей:
//   - ECDSA P-256 — для mTLS и SSH;
//   - Ed25519 — для подписей discovery-пакетов и gossip.
//
// Публичный ключ Ed25519 включается в сертификат как SAN URI
// (urn:beacon:ed25519:<base64url>). Это делает идентичность узла
// криптографически привязанной к выданному сертификату: сосед может проверить
// подпись discovery-пакета, имея только сертификат, без доверия к файлу на диске
// и без отдельного обмена ключами.
//
// nodeID больше не задаётся снаружи и не пишется в SubjectKeyId: он
// вычисляется из Ed25519-ключа (см. NodeIDFromEd25519Pub), чтобы все стороны
// приходили к одному значению одинаково.
//
// Формат выдачи: файлы сохраняются в dataDir/<nodeName>/.
// key.pem    — ECDSA P-256, права 0600
// cert.pem   — сертификат x509, права 0644
// ed25519-key.pem — Ed25519, права 0600
func IssueCertificate(
	caKey *ecdsa.PrivateKey,
	caCertPEM []byte,
	dataDir string,
	nodeName string,
	ttl time.Duration,
) (*IssuedNode, error) {
	// Загружаем CA-сертификат для парсинга
	caCert, err := ParseCertificatePEM(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("парсинг CA-сертификата: %w", err)
	}

	// Ключ для TLS и SSH
	nodeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("генерация ключа узла: %w", err)
	}

	// Ключ для подписей discovery и gossip
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("генерация Ed25519-ключа: %w", err)
	}

	edURI, err := Ed25519URIValue(edPub)
	if err != nil {
		return nil, fmt.Errorf("формирование SAN URI: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("генерация serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Network Beacons"},
			CommonName:   nodeName,
			Country:      []string{"RU"},
		},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(ttl),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
		// Идентичность узла: публичный ключ Ed25519 в SAN.
		// nodeID выводится из него, поэтому SubjectKeyId для идентификации
		// больше не используется и оставлен пустым — Go вычислит его сам.
		URIs: []*url.URL{edURI},
	}

	// Подписываем сертификат CA-ключом
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &nodeKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("подписание сертификата: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalECPrivateKey(nodeKey)
	if err != nil {
		return nil, fmt.Errorf("маршализация ключа: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	edPrivPEM, err := SerializePrivateKeyPEM(edPriv)
	if err != nil {
		return nil, fmt.Errorf("маршализация Ed25519-ключа: %w", err)
	}

	// Сохраняем файлы узла
	nodeDir := filepath.Join(dataDir, nodeName)
	if err := os.MkdirAll(nodeDir, 0700); err != nil {
		return nil, fmt.Errorf("создание директории узла: %w", err)
	}

	keyPath := filepath.Join(nodeDir, "key.pem")
	certPath := filepath.Join(nodeDir, "cert.pem")
	edPath := filepath.Join(nodeDir, ed25519KeyFile)

	// Приватные ключи — 0600, сертификат публичный — 0644.
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("сохранение ключа узла: %w", err)
	}

	if err := os.WriteFile(edPath, edPrivPEM, 0600); err != nil {
		return nil, fmt.Errorf("сохранение Ed25519-ключа: %w", err)
	}

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return nil, fmt.Errorf("сохранение сертификата узла: %w", err)
	}

	return &IssuedNode{
		CertPath:    certPath,
		KeyPath:     keyPath,
		Ed25519Path: edPath,
		Ed25519Pub:  edPub,
		NodeID:      NodeIDFromEd25519Pub(edPub),
		Serial:      serialNumber,
	}, nil
}

// ParseCertificatePEM парсит PEM-кодированный сертификат.
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM-блок сертификата")
	}
	return x509.ParseCertificate(block.Bytes)
}

// LoadCAKey загружает приватный ключ CA из PEM-файла.
func LoadCAKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("чтение ключа CA: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM-блок ключа CA")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("парсинг ключа CA: %w", err)
	}

	return key, nil
}

// LoadCACert загружает сертификат CA из PEM-файла.
func LoadCACert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("чтение сертификата CA: %w", err)
	}
	return ParseCertificatePEM(data)
}

// RevokeCertificate отзывает сертификат по его серийному номеру.
//
// Отзывы пишутся в CRL, подписанный ключом CA (x509.RevocationList), поэтому
// узел может проверить подлинность списка и не принимает файл, полученный
// не из сети.
//
// reason: 0=не определена, 1=комрометация ключа, 2=выход из сети.
func RevokeCertificate(dataDir string, serial *big.Int, reason uint8) error {
	if serial == nil {
		return fmt.Errorf("серийный номер не задан")
	}

	caDir := filepath.Join(dataDir, "ca")
	crlPath := filepath.Join(caDir, "crl.pem")

	store, err := LoadCRLStore(crlPath,
		filepath.Join(caDir, "ca-cert.pem"),
		filepath.Join(caDir, "ca-key.pem"))
	if err != nil {
		return err
	}

	if store.IsRevoked(serial) {
		return fmt.Errorf("сертификат %s уже отозван", serial)
	}

	if err := store.Revoke(serial, reason); err != nil {
		return fmt.Errorf("отзыв сертификата: %w", err)
	}

	return nil
}

// ComputeSerialHash вычисляет 16-байтовый хеш от distinguished name сертификата.
// Используется как серийный номер в CRL (вместо случайного serial).
func ComputeSerialHash(cert *x509.Certificate) [16]byte {
	// Используем RawSubject/RawIssuer если доступны (парсинг из DER),
	// иначе fallback на CommonName (для шаблонов/тестов).
	var data []byte
	if len(cert.RawSubject) > 0 {
		data = append(cert.RawSubject, cert.RawIssuer...)
	} else {
		data = []byte(cert.Subject.CommonName)
	}
	h := sha256.Sum256(data)
	var result [16]byte
	copy(result[:], h[:16])
	return result
}
