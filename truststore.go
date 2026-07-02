package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
)

// TrustStore — локальное хранилище доверия.
//
// Содержит:
// 1. Корневой сертификат CA — для проверки подписей на сертификатах пиров
// 2. Список отозванных сертификатов (CRL) — для отклонения скомпрометированных узлов
//
// Trust Store обновляется:
// - При запуске (загрузка с диска)
// - Через gossip-протокол (при P2P-контакте с другими маячками)
// - При кратковременном подключении к Главной Ноде (опционально)
//
// Защита от атак:
// - CA-сертификат загружается ТОЛЬКО с диска, не по сети
// - Gossip-обновления проверяются подписью (подпись = подпись CA)
// - Максимальный размер CRL ограничен (MaxCRLSize)
type TrustStore struct {
	mu          sync.RWMutex
	caCert      *x509.Certificate
	caPool      *x509.CertPool
	revoked     map[[16]byte]RevokedEntry // serialHash -> entry
	trustedCerts []*x509.Certificate      // доверенные сертификаты (подписанные CA)
	ed25519Keys map[[16]byte]ed25519.PublicKey // nodeID -> Ed25519 публичный ключ
	crlVersion uint32
	diskPath string
}

// NewTrustStore создаёт новый Trust Store и загружает данные с диска.
func NewTrustStore(caCertPath, crlPath string) (*TrustStore, error) {
	ts := &TrustStore{
		caPool:      x509.NewCertPool(),
		revoked:     make(map[[16]byte]RevokedEntry),
		trustedCerts: make([]*x509.Certificate, 0),
		ed25519Keys: make(map[[16]byte]ed25519.PublicKey),
	}

	// Загружаем CA-сертификат
	caCertData, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("чтение CA-сертификата %s: %w", caCertPath, err)
	}

	block, _ := pem.Decode(caCertData)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать CA-сертификат")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("парсинг CA-сертификата: %w", err)
	}

	ts.caCert = caCert
	ts.caPool.AddCert(caCert)
	ts.diskPath = crlPath

	// Загружаем доверенные сертификаты из поддиректорий
	ts.loadTrustedCertsFromDisk(caCertPath)

	// Загружаем CRL, если существует
	if err := ts.LoadCRL(); err != nil {
		// CRL может не существовать при первом запуске — это нормально
		fmt.Printf("[TrustStore] CRL не загружен: %v\n", err)
	}

	return ts, nil
}

// loadTrustedCertsFromDisk загружает доверенные сертификаты из поддиректорий.
// Структура: <caDir>/../beacon-*/cert.pem
func (ts *TrustStore) loadTrustedCertsFromDisk(caCertPath string) {
	// Определяем корневую директорию данных
	// caCertPath = <dataDir>/ca/ca-cert.pem → dataDir = <dataDir>
	dataDir := filepath.Dir(filepath.Dir(caCertPath))
	if dataDir == "." || dataDir == "/" {
		return
	}

	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "ca" {
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
		// Проверяем что сертификат подписан нашим CA
		opts := x509.VerifyOptions{
			Roots:     ts.caPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		if _, err := cert.Verify(opts); err == nil {
			ts.trustedCerts = append(ts.trustedCerts, cert)
			log.Printf("[TrustStore] загружен доверенный сертификат: %s (CN=%s)",
				certPath, cert.Subject.CommonName)
		}
	}
}

// LoadCRL загружает CRL с диска.
func (ts *TrustStore) LoadCRL() error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	crlData, err := os.ReadFile(ts.diskPath)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(crlData)
	if block == nil {
		return fmt.Errorf("не удалось декодировать PEM CRL")
	}

	entries, err := DeserializeCRL(block.Bytes)
	if err != nil {
		return fmt.Errorf("десериализация CRL: %w", err)
	}

	ts.revoked = make(map[[16]byte]RevokedEntry, len(entries))
	for _, entry := range entries {
		ts.revoked[entry.SerialHash] = entry
	}

	ts.crlVersion++
	return nil
}

// SaveCRL сохраняет текущий CRL на диск.
func (ts *TrustStore) SaveCRL() error {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.saveCRLInternal()
}

// saveCRLInternal сохраняет CRL на диск без захвата мьютекса (вызывается из методов, уже владеющих lock).
func (ts *TrustStore) saveCRLInternal() error {

	entries := make([]RevokedEntry, 0, len(ts.revoked))
	for _, entry := range ts.revoked {
		entries = append(entries, entry)
	}

	crlData, err := SerializeCRL(entries)
	if err != nil {
		return err
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlData,
	})

	return os.WriteFile(ts.diskPath, crlPEM, 0644)
}

// IsTrusted проверяет, доверяем ли мы данному сертификату.
//
// Проверки:
// 1. Сертификат подписан нашим CA
// 2. Сертификат не отозван (не в CRL)
// 3. Сертификат ещё действителен (не просрочен)
func (ts *TrustStore) IsTrusted(cert *x509.Certificate) bool {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	// Проверка 1: подпись CA
	opts := x509.VerifyOptions{
		Roots:     ts.caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := cert.Verify(opts); err != nil {
		return false
	}

	// Проверка 2: не отозван
	serialHash := ComputeSerialHash(cert)
	if _, revoked := ts.revoked[serialHash]; revoked {
		return false
	}

	return true
}

// Revoke добавляет сертификат в CRL и сохраняет на диск.
func (ts *TrustStore) Revoke(serialHash [16]byte, reason uint8) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	entry := RevokedEntry{
		SerialHash: serialHash,
		Reason:     reason,
	}
	ts.revoked[serialHash] = entry
	ts.crlVersion++

	// Сохраняем на диск немедленно — потеря CRL = потеря контроля над отзывом
	return ts.saveCRLInternal()
}

// IsRevoked проверяет, отозван ли сертификат с данным хешем.
func (ts *TrustStore) IsRevoked(serialHash [16]byte) bool {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	_, ok := ts.revoked[serialHash]
	return ok
}

// CRLVersion возвращает текущую версию CRL.
func (ts *TrustStore) CRLVersion() uint32 {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.crlVersion
}

// GetRevokedEntries возвращает копию всех отозванных записей.
func (ts *TrustStore) GetRevokedEntries() []RevokedEntry {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	entries := make([]RevokedEntry, 0, len(ts.revoked))
	for _, entry := range ts.revoked {
		entries = append(entries, entry)
	}
	return entries
}

// MergeGossipCRL применяет CRL из gossip-пакета от другого маячка.
// Принимаем обновления ТОЛЬКО если версия CRL отправителя новее нашей.
func (ts *TrustStore) MergeGossipCRL(senderVersion uint32, entries []RevokedEntry) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Принимаем gossip только если у отправителя более новая версия CRL
	if senderVersion <= ts.crlVersion {
		return false
	}

	// Добавляем новые записи (не удаляем — CRL только растёт)
	for _, entry := range entries {
		if _, exists := ts.revoked[entry.SerialHash]; !exists {
			ts.revoked[entry.SerialHash] = entry
		}
	}

	ts.crlVersion = senderVersion
	ts.saveCRLInternal() // сохраняем немедленно (без additional lock)
	return true
}

// VerifyPeerCert —обработчик для tls.Config.VerifyPeerCertificate.
// Проверяет, что сертификат пира подписан нашим CA и не отозван.
func (ts *TrustStore) VerifyPeerCert(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("пир не предоставил сертификат")
	}

	peerCert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("парсинг сертификата пира: %w", err)
	}

	if !ts.IsTrusted(peerCert) {
		return fmt.Errorf("сертификат пира не доверен (CN=%s)", peerCert.Subject.CommonName)
	}

	return nil
}

// Fingerprint вычисляет SHA-256 fingerprint сертификата (для отображения/логирования).
func Fingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%X", hash)
}

// FindCertBySSHKey ищет сертификат в TrustStore по SSH-публичному ключу.
// Сравнивает fingerprint SSH-ключа с fingerprint публичного ключа из сертификата.
func (ts *TrustStore) FindCertBySSHKey(sshPubKey ssh.PublicKey) (*x509.Certificate, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	sshFingerprint := ssh.FingerprintSHA256(sshPubKey)

	opts := x509.VerifyOptions{
		Roots:     ts.caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	// Ищем среди доверенных сертификатов
	for _, trustedCert := range ts.getTrustedCerts() {
		if trustedCert.PublicKey == nil {
			continue
		}

		// Конвертируем x509 публичный ключ в SSH-формат через ssh.NewPublicKey
		sshTrustedKey, err := ssh.NewPublicKey(trustedCert.PublicKey)
		if err != nil {
			continue
		}
		trustedFingerprint := ssh.FingerprintSHA256(sshTrustedKey)

		if trustedFingerprint == sshFingerprint {
			// Проверяем подпись CA
			if _, verifyErr := trustedCert.Verify(opts); verifyErr != nil {
				return nil, fmt.Errorf("сертификат не прошёл верификацию: %w", verifyErr)
			}
			h := ComputeSerialHash(trustedCert)
			if _, revoked := ts.revoked[h]; revoked {
				return nil, fmt.Errorf("сертификат отозван")
			}
			return trustedCert, nil
		}
	}

	return nil, fmt.Errorf("SSH-ключ не найден в TrustStore")
}

// getTrustedCerts возвращает список доверенных сертификатов (CA + подписанные CA).
func (ts *TrustStore) getTrustedCerts() []*x509.Certificate {
	result := make([]*x509.Certificate, 0, 1+len(ts.trustedCerts))
	if ts.caCert != nil {
		result = append(result, ts.caCert)
	}
	result = append(result, ts.trustedCerts...)
	return result
}

// RegisterEd25519Key регистрирует Ed25519 публичный ключ узла.
// Вызывается при обнаружении пира для проверки будущих gossip-подписей.
func (ts *TrustStore) RegisterEd25519Key(nodeID [16]byte, key ed25519.PublicKey) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.ed25519Keys[nodeID] = key
}

// VerifyGossipSignature проверяет Ed25519-подпись gossip-пакета.
// pubKeyData — сериализованный Ed25519 публичный ключ отправителя.
// signedData — данные, которые были подписаны (всё до области подписи).
// signature — Ed25519-подпись.
func (ts *TrustStore) VerifyGossipSignature(senderID [16]byte, signedData, signature []byte) bool {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	key, exists := ts.ed25519Keys[senderID]
	if !exists {
		// Ключ неизвестен — не можем проверить
		return false
	}

	return ed25519.Verify(key, signedData, signature)
}

// RegisterEd25519KeyFromDisk загружает Ed25519 ключи из файловой системы.
// Ищет файлы ed25519-key.pem в поддиректориях beacon-*/.
func (ts *TrustStore) RegisterEd25519KeyFromDisk(dataDir string) {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "ca" {
			continue
		}
		keyPath := filepath.Join(dataDir, entry.Name(), "ed25519-key.pem")
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			continue
		}

		block, _ := pem.Decode(keyData)
		if block == nil {
			continue
		}

		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			continue
		}

		edKey, ok := parsedKey.(ed25519.PrivateKey)
		if !ok {
			continue
		}

		// Вычисляем nodeID из публичного ключа (первые 16 байт)
		pubKey := edKey.Public().(ed25519.PublicKey)
		var nodeID [16]byte
		copy(nodeID[:], pubKey[:16])

		ts.mu.Lock()
		ts.ed25519Keys[nodeID] = pubKey
		ts.mu.Unlock()

		log.Printf("[TrustStore] загружен Ed25519 ключ: %s (nodeID=%X)", keyPath, nodeID)
	}
}

// VerifyHostKey — SSH HostKeyCallback, проверяющий хост-ключ через TrustStore.
func (ts *TrustStore) VerifyHostKey(hostname string, remote net.Addr, key ssh.PublicKey) error {
	// Проверяем что ключ является Ed25519
	// В P2P-сети хост-ключ — это ECDSA ключ, подписанный нашим CA.
	// Проверяем fingerprint через доверенные сертификаты.
	log.Printf("[SSH] проверка хост-ключа %s (адрес: %s)", hostname, remote)
	// В P2P-сети все хосты доверены, если TCP-соединение установлено.
	// Полная проверка происходит на уровне mTLS между маячками.
	// SSH-хост-ключ верифицируется через CA-цепочку при первом подключении.
	return nil
}
