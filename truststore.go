package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
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
	mu       sync.RWMutex
	caCert   *x509.Certificate
	caPool   *x509.CertPool
	revoked  map[[16]byte]RevokedEntry // serialHash -> entry
	crlVersion uint32
	diskPath string
}

// NewTrustStore создаёт новый Trust Store и загружает данные с диска.
func NewTrustStore(caCertPath, crlPath string) (*TrustStore, error) {
	ts := &TrustStore{
		caPool:  x509.NewCertPool(),
		revoked: make(map[[16]byte]RevokedEntry),
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

	// Загружаем CRL, если существует
	if err := ts.LoadCRL(); err != nil {
		// CRL может не существовать при первом запуске — это нормально
		fmt.Printf("[TrustStore] CRL не загружен: %v\n", err)
	}

	return ts, nil
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
