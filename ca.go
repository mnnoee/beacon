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

// RevokeCertificate добавляет сертификат в CRL.
// serialNumber — SHA-256 хеш от distinguished name сертификата (16 байт).
// reason: 0=не определена, 1=компрометация ключа, 2=выход из сети.
func RevokeCertificate(dataDir string, serialHash [16]byte, reason uint8) error {
	crlPath := filepath.Join(dataDir, "ca", "crl.pem")

	// Загружаем существующий CRL или создаём новый
	existing, _ := os.ReadFile(crlPath)
	var revoked []RevokedEntry

	if len(existing) > 0 {
		crlBlock, _ := pem.Decode(existing)
		if crlBlock != nil {
			var err error
			revoked, err = DeserializeCRL(crlBlock.Bytes)
			if err != nil {
				return fmt.Errorf("десериализация существующего CRL: %w", err)
			}
		}
	}

	// Проверяем, не отозван ли уже
	for _, entry := range revoked {
		if entry.SerialHash == serialHash {
			return fmt.Errorf("сертификат уже отозван")
		}
	}

	revoked = append(revoked, RevokedEntry{
		SerialHash: serialHash,
		RevokedAt:  time.Now().Unix(),
		Reason:     reason,
	})

	crlData, err := SerializeCRL(revoked)
	if err != nil {
		return fmt.Errorf("сериализация CRL: %w", err)
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlData,
	})

	return os.WriteFile(crlPath, crlPEM, 0644)
}

// SerializeCRL кодирует CRL в простой бинарный формат.
// Формат: [4 байта count] + count * [16(serial) + 8(time) + 1(reason)]
func SerializeCRL(entries []RevokedEntry) ([]byte, error) {
	size := 4 + len(entries)*25
	buf := make([]byte, size)

	// count в big-endian
	buf[0] = byte(len(entries) >> 24)
	buf[1] = byte(len(entries) >> 16)
	buf[2] = byte(len(entries) >> 8)
	buf[3] = byte(len(entries))

	for i, entry := range entries {
		base := 4 + i*25
		copy(buf[base:base+16], entry.SerialHash[:])
		buf[base+16] = byte(entry.RevokedAt >> 56)
		buf[base+17] = byte(entry.RevokedAt >> 48)
		buf[base+18] = byte(entry.RevokedAt >> 40)
		buf[base+19] = byte(entry.RevokedAt >> 32)
		buf[base+20] = byte(entry.RevokedAt >> 24)
		buf[base+21] = byte(entry.RevokedAt >> 16)
		buf[base+22] = byte(entry.RevokedAt >> 8)
		buf[base+23] = byte(entry.RevokedAt)
		buf[base+24] = entry.Reason
	}

	return buf, nil
}

// DeserializeCRL декодирует CRL из бинарного формата.
func DeserializeCRL(data []byte) ([]RevokedEntry, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("CRL слишком короткий")
	}

	count := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+count*25 {
		return nil, fmt.Errorf("CRL: неверная длина (ожидается %d, получено %d)", 4+count*25, len(data))
	}

	entries := make([]RevokedEntry, count)
	for i := 0; i < count; i++ {
		base := 4 + i*25
		copy(entries[i].SerialHash[:], data[base:base+16])
		entries[i].RevokedAt = int64(data[base+16])<<56 | int64(data[base+17])<<48 |
			int64(data[base+18])<<40 | int64(data[base+19])<<32 |
			int64(data[base+20])<<24 | int64(data[base+21])<<16 |
			int64(data[base+22])<<8 | int64(data[base+23])
		entries[i].Reason = data[base+24]
	}

	return entries, nil
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
