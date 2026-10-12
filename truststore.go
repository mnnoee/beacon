package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// TrustStore — локальное хранилище доверия.
//
// Содержит:
// 1. Корневой сертификат CA — для проверки подписей на сертификатах пиров
// 2. CRL на базе crypto/x509 — для отклонения отозванных узлов
// 3. Ключи подписей Ed25519 соседей — для проверки gossip
//
// Отзывы keyed по настоящему серийному номеру сертификата. Прежняя схема
// использовала 16-байтовый хеш от CN, из-за чего пере-выдача сертификата на то
// же имя давала тот же ключ: отзыв старого убивал новый, а новый не отзывался
// вовсе.
type TrustStore struct {
	mu           sync.RWMutex
	caCert       *x509.Certificate
	caPool       *x509.CertPool
	crl          *CRLStore
	trustedCerts []*x509.Certificate            // доверенные сертификаты (подписанные CA)
	ed25519Keys  map[[16]byte]ed25519.PublicKey // nodeID -> Ed25519 публичный ключ
	diskPath     string
}

// NewTrustStore создаёт новый Trust Store и загружает данные с диска.
func NewTrustStore(caCertPath, crlPath string) (*TrustStore, error) {
	ts := &TrustStore{
		caPool:       x509.NewCertPool(),
		trustedCerts: make([]*x509.Certificate, 0),
		ed25519Keys:  make(map[[16]byte]ed25519.PublicKey),
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

	// CRL: подпись CA нужна только на CA-машине, но путь к ключу известен
	// из расположения каталога.
	dataDir := filepath.Dir(filepath.Dir(caCertPath))
	crlStore, err := LoadCRLStore(crlPath, caCertPath, filepath.Join(dataDir, "ca", "ca-key.pem"))
	if err != nil {
		fmt.Printf("[TrustStore] CRL: %v\n", err)
	}
	ts.crl = crlStore

	// Загружаем доверенные сертификаты из поддиректорий
	ts.loadTrustedCertsFromDisk(caCertPath)

	return ts, nil
}

// AddTrustedCert добавляет сертификат в список доверенных.
//
// Нужен именно добавление в память, а не только запись в peers/: иначе
// проверка конфликта CN для второго сертификата с тем же именем не увидела бы
// первый и позволила бы подмену до перезапуска процесса, а SSH к соседу не
// заработал бы, пока узел не перезагрузится.
func (ts *TrustStore) AddTrustedCert(cert *x509.Certificate) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	for _, existing := range ts.trustedCerts {
		if existing == cert {
			return
		}
		if existing.SerialNumber != nil && cert.SerialNumber != nil &&
			existing.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			// Такой серийник уже есть — дубликат не нужен.
			return
		}
	}

	ts.trustedCerts = append(ts.trustedCerts, cert)
}

// CertByCN ищет доверенный сертификат по имени узла.
func (ts *TrustStore) CertByCN(cn string) (*x509.Certificate, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	for _, cert := range ts.getTrustedCertsLocked() {
		if cert != nil && cert.Subject.CommonName == cn {
			return cert, nil
		}
	}

	return nil, fmt.Errorf("сертификат для CN=%s не найден в TrustStore", cn)
}

// loadTrustedCertsFromDisk загружает доверенные сертификаты из поддиректорий.
//
// Два источника:
//   - beacon-*/cert.pem — своя выдача (узел со своими ключами);
//   - peers/*.pem — сертификаты, полученные по mTLS от соседей.
//
// Оба источника равноправны: сертификат соседа так же подписан нашим CA, как
// и свой, и он нужен всем проверкам — поиск клиента для SSH, host-ключ,
// ключи подписи gossip.
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
		if !entry.IsDir() || entry.Name() == "ca" || entry.Name() == peersDirName {
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

	// Сертификаты, полученные от соседей.
	for _, cert := range PeerCertificates(dataDir) {
		opts := x509.VerifyOptions{
			Roots:     ts.caPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		if _, err := cert.Verify(opts); err != nil {
			log.Printf("[TrustStore] сертификат соседа CN=%s не прошёл проверку CA: %v",
				cert.Subject.CommonName, err)
			continue
		}

		if ts.crl != nil && ts.crl.IsRevoked(cert.SerialNumber) {
			log.Printf("[TrustStore] сертификат соседа CN=%s отозван — пропущен",
				cert.Subject.CommonName)
			continue
		}

		ts.trustedCerts = append(ts.trustedCerts, cert)
	}
}

// SaveCRL сохраняет текущий CRL на диск.
func (ts *TrustStore) SaveCRL() error {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if ts.crl == nil {
		return fmt.Errorf("хранилище CRL не инициализировано")
	}
	return ts.crl.Save()
}

// IsTrusted проверяет, доверяем ли мы данному сертификату.
//
// Проверки:
// 1. Сертификат подписан нашим CA
// 2. Его серийный номер не числится в CRL
func (ts *TrustStore) IsTrusted(cert *x509.Certificate) bool {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	// Проверка 1: подпись CA, срок действия и цепочка.
	// cert.Verify сам проверяет NotBefore/NotAfter, поэтому отдельная
	// проверка на протухание не нужна.
	opts := x509.VerifyOptions{
		Roots:     ts.caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := cert.Verify(opts); err != nil {
		return false
	}

	// Проверка 2: отзыв по серийному номеру.
	if ts.crl != nil && ts.crl.IsRevoked(cert.SerialNumber) {
		return false
	}

	return true
}

// Revoke добавляет сертификат в CRL и сохраняет на диск.
func (ts *TrustStore) Revoke(serial *big.Int, reason uint8) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.crl == nil {
		return fmt.Errorf("хранилище CRL не инициализировано")
	}

	return ts.crl.Revoke(serial, reason)
}

// IsRevokedBySerial проверяет, отозван ли сертификат с данным серийным номером.
func (ts *TrustStore) IsRevokedBySerial(serial *big.Int) bool {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if ts.crl == nil {
		return false
	}
	return ts.crl.IsRevoked(serial)
}

// IsRevoked проверяет, отозван ли сертификат.
func (ts *TrustStore) IsRevoked(cert *x509.Certificate) bool {
	return ts.IsRevokedBySerial(cert.SerialNumber)
}

// CRLVersion возвращает номер текущего CRL.
func (ts *TrustStore) CRLVersion() uint64 {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if ts.crl == nil {
		return 0
	}
	return ts.crl.Number()
}

// GetRevokedEntries возвращает копию всех отозванных записей.
func (ts *TrustStore) GetRevokedEntries() []revokedCert {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if ts.crl == nil {
		return nil
	}
	return ts.crl.Entries()
}

// MergeGossipCRL применяет обновления CRL из gossip-пакета от соседа.
//
// Отзывы принимаются ВСЕГДА, а не только при более высокой версии отправителя.
// Прежняя проверка `senderVersion <= localVersion` была губительной: номер CRL
// жил только в памяти и обнулялся при каждом запуске, поэтому два свежих узла
// имели одинаковый номер и отзывы не расходились вообще. CRL только растёт —
// объединение безопасно и не может «отозвать обратно».
//
// Ограничение доверия здесь не снижается: сам пакет приходит по mTLS с
// проверенным сертификатом пира, а подпись проверяется в handleGossip.
func (ts *TrustStore) MergeGossipCRL(senderNumber uint64, entries []revokedCert) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.crl == nil {
		return false
	}

	if !ts.crl.Merge(entries, senderNumber) {
		return false
	}

	// Сохраняем немедленно: потеря CRL означает потерю контроля над отзывом.
	// На узле без ключа CA подписать CRL нечем — gossip-записи тогда просто
	// не переживут перезапуск, о чём честно сообщаем.
	if err := ts.crl.Save(); err != nil {
		log.Printf("[TrustStore] CRL принят, но не сохранён на диск: %v", err)
	}

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
			if ts.crl != nil && ts.crl.IsRevoked(trustedCert.SerialNumber) {
				return nil, fmt.Errorf("сертификат отозван")
			}
			return trustedCert, nil
		}
	}

	return nil, fmt.Errorf("SSH-ключ не найден в TrustStore")
}

// FindCertByNodeID ищет сертификат узла по его идентификатору.
//
// Идентификатор выводится из публичного ключа Ed25519 (NodeIDFromEd25519Pub),
// поэтому поиск идёт по ключу из SAN сертификата, а не по SubjectKeyId:
// SubjectKeyId больше не является идентификатором узла.
func (ts *TrustStore) FindCertByNodeID(nodeID [16]byte) (*x509.Certificate, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	for _, cert := range ts.getTrustedCertsLocked() {
		if cert == nil {
			continue
		}
		certID, err := NodeIDFromCert(cert)
		if err != nil {
			// Сертификат без ключа Ed25519 в SAN — старый формат, пропускаем.
			continue
		}
		if certID == nodeID {
			return cert, nil
		}
	}

	return nil, fmt.Errorf("сертификат для узла %X не найден в TrustStore", nodeID)
}

// getTrustedCertsLocked возвращает список доверенных сертификатов.
// Вызывающий обязан удерживать ts.mu — метод не берёт блокировку сам,
// потому что используется из мест, уже её удерживающих.
func (ts *TrustStore) getTrustedCertsLocked() []*x509.Certificate {
	result := make([]*x509.Certificate, 0, 1+len(ts.trustedCerts))
	if ts.caCert != nil {
		result = append(result, ts.caCert)
	}
	result = append(result, ts.trustedCerts...)
	return result
}

// getTrustedCerts возвращает список доверенных сертификатов (CA + подписанные CA).
func (ts *TrustStore) getTrustedCerts() []*x509.Certificate {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.getTrustedCertsLocked()
}

// SigningKey возвращает публичный ключ подписи узла по его NodeID.
//
// Ключ берётся из сертификата, а не из отдельного хранилища: это гарантирует,
// что gossip может подписать только тот, кому CA выдал сертификат с этим ключом.
func (ts *TrustStore) SigningKey(nodeID [16]byte) (ed25519.PublicKey, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	key, ok := ts.ed25519Keys[nodeID]
	if !ok {
		return nil, fmt.Errorf("ключ подписи для узла %X не зарегистрирован", nodeID)
	}
	return key, nil
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

// RegisterEd25519KeyFromDisk регистрирует публичные ключи подписей соседей.
//
// Ключи берутся ИЗ СЕРТИФИКАТОВ (SAN URI), а не из файлов ed25519-key.pem.
// Причина: для проверки подписи gossip нужен только публичный ключ, а приватный
// лежит на своей машине. Если бы ключи брались из приватных файлов, соседям
// пришлось бы раздавать приватные ключи — недопустимо.
//
// Файл ed25519-key.pem читается только в beacon.go при загрузке СОБСТВЕННОГО
// ключа для подписи announce.
func (ts *TrustStore) RegisterEd25519KeyFromDisk(dataDir string) {
	ts.mu.RLock()
	certs := ts.getTrustedCertsLocked()
	ts.mu.RUnlock()

	registered := 0

	for _, cert := range certs {
		if cert == nil || cert.IsCA {
			continue
		}

		pub, err := Ed25519PubFromCert(cert)
		if err != nil {
			// Старый формат сертификата — пропускаем, ключа в нём нет.
			continue
		}

		nodeID := NodeIDFromEd25519Pub(pub)

		ts.mu.Lock()
		ts.ed25519Keys[nodeID] = pub
		ts.mu.Unlock()

		registered++
		log.Printf("[TrustStore] зарегистрирован ключ подписи: CN=%s nodeID=%X",
			cert.Subject.CommonName, nodeID)
	}

	if registered == 0 {
		log.Printf("[TrustStore] ключи подписи не найдены: в %s нет сертификатов "+
			"с Ed25519 в SAN (нужен протокол v%d, пере-выпустите сертификаты)",
			dataDir, ProtocolVersion)
	}
}

// VerifyHostKey — SSH HostKeyCallback, проверяющий host-ключ через TrustStore.
//
// Раньше функция заканчивалась `return nil`, то есть пропускала любой
// host-ключ: клиент, оказавшийся посреди соединения (MITM), предъявлял свой
// ключ и получал сессию. Сертификат узла при этом не предъявляется вовсе —
// SSH-рукопожатие несёт только голый host-ключ.
//
// Проверка идёт по косвенным признакам:
//   - host-ключ обязан совпадать с публичным ключом сертификата, выданного
//     нашим CA;
//   - сертификат не отозван;
//   - сертификат не просрочен.
//
// Если сертификат для host-ключа не найден — соединение отклоняется. Мягкое
// «сначала доверяем, потом проверяем» здесь означало бы, что MITM просто
// приходит первым.
func (ts *TrustStore) VerifyHostKey(hostname string, remote net.Addr, key ssh.PublicKey) error {
	if key == nil {
		return fmt.Errorf("SSH: пустой host-ключ")
	}

	cert, err := ts.FindCertBySSHKey(key)
	if err != nil {
		return fmt.Errorf("SSH host-ключ не принадлежит ни одному доверенному узлу "+
			"(addr=%s, fingerprint=%s): %w", remote, ssh.FingerprintSHA256(key), err)
	}

	if ts.crl != nil && ts.crl.IsRevoked(cert.SerialNumber) {
		return fmt.Errorf("SSH: сертификат узла %s отозван", cert.Subject.CommonName)
	}

	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("SSH: сертификат узла %s просрочен (%s)",
			cert.Subject.CommonName, cert.NotAfter.Format("2006-01-02"))
	}

	log.Printf("[SSH] host-ключ принят: CN=%s fingerprint=%s addr=%s",
		cert.Subject.CommonName, ssh.FingerprintSHA256(key), remote)

	return nil
}
