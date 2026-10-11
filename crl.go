package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// crlPEMType — тип PEM-блока для CRL (RFC 7468), как это делает сам Go.
const crlPEMType = "X509 CRL"

// crlLegacyBackupSuffix — суффикс резервной копии старого формата CRL.
const crlLegacyBackupSuffix = ".v1.bak"

// revokedCacheFileName — имя локального кэша полученных отзывов.
const revokedCacheFileName = "revoked-cache.json"

// DefaultCRLUpdateInterval — как часто продлевается CRL на CA-машине.
const DefaultCRLUpdateInterval = 24 * time.Hour

// revokedCert — запись об отозванном сертификате внутри TrustStore.
//
// Ключ отзыва — настоящий серийный номер сертификата (*big.Int), а не хеш
// от CN. Прежняя схема ломалась при пере-выдаче: хеш считался от RawSubject,
// поэтому все сертификаты с одинаковым CN получали один и тот же ключ, и
// отзыв старого убивал новый. Серийник уникален на каждую выдачу.
type revokedCert struct {
	SerialNumber *big.Int
	RevokedAt    time.Time
	Reason       uint8
}

// CRLStore — хранилище отозванных сертификатов на базе crypto/x509.
//
// Отказ от собственного бинарного формата в пользу x509.RevocationList даёт:
//   - настоящую подпись CA ключом с KeyUsageCRLSign — раньше CRL была
//     подписана чем угодно, и подделка не отличалась от настоящей;
//   - CRLNumber для сравнения версий (прежний счётчик жил только в памяти
//     и обнулялся при каждом запуске, из-за чего gossip не работал);
//   - ThisUpdate/NextUpdate — можно отбрасывать протухшие CRL;
//   - стандартный парсер вместо ~50 строк собственного кода.
type CRLStore struct {
	// revoked — отзывы по серийному номеру.
	revoked map[string]revokedCert

	// number — монотонный номер CRL (CRLNumber). 0 = CRL ещё не выпущен.
	number uint64

	// thisUpdate, nextUpdate — окно действия CRL.
	thisUpdate time.Time
	nextUpdate time.Time

	// diskPath — путь к PEM-файлу CRL.
	diskPath string

	// cachePath — локальный кэш отзывов, полученных по gossip.
	//
	// Нужен потому, что подписать CRL может только CA: у обычного маячка
	// нет ca/ca-key.pem, поэтому принятые по gossip отзывы некуда записать
	// в подписанном виде. Без такого кэша отзыв держался бы только в памяти
	// и исчезал при перезапуске — отозванный узел возвращался бы в сеть
	// после ребута соседа.
	cachePath string

	// caCert, caKey — нужны для подписи новых CRL.
	caCert *x509.Certificate
	caKey  crypto.Signer
}

// revokedCacheVersion — формат локального кэша отзывов.
const revokedCacheVersion = 1

// revokedCacheFile — сериализуемая форма кэша отзывов.
//
// Серийник хранится строкой: json не умеет *big.Int, а десятичная запись
// совпадает с форматом индекса CA.
type revokedCacheFile struct {
	Version int                 `json:"version"`
	Number  uint64              `json:"number"`
	Entries []revokedCacheEntry `json:"entries"`
}

type revokedCacheEntry struct {
	Serial string `json:"serial"`
	At     int64  `json:"revoked_at"`
	Reason uint8  `json:"reason"`
}

// saveCache сохраняет отзывы в локальный кэш.
//
// Файл подписи CA не несёт — и это нормально: он пополняется только
// записями, проверенными при получении (mTLS + подпись gossip), и читается
// на той же машине. Ровно на тех же условиях, что и ca-cert.pem, который тоже
// берут с диска без проверки подписи.
func (s *CRLStore) saveCache() error {
	if s.cachePath == "" {
		return nil
	}

	cache := revokedCacheFile{
		Version: revokedCacheVersion,
		Number:  s.number,
		Entries: make([]revokedCacheEntry, 0, len(s.revoked)),
	}

	for _, e := range s.Entries() {
		cache.Entries = append(cache.Entries, revokedCacheEntry{
			Serial: e.SerialNumber.String(),
			At:     e.RevokedAt.Unix(),
			Reason: e.Reason,
		})
	}

	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("сериализация кэша отзывов: %w", err)
	}

	tmp := s.cachePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("запись кэша отзывов: %w", err)
	}
	if err := os.Rename(tmp, s.cachePath); err != nil {
		return fmt.Errorf("сохранение кэша отзывов: %w", err)
	}

	return nil
}

// loadCache подмешивает отзывы, сохранённые ранее.
//
// Ошибка чтения не фатальна: отсутствие или порча кэша означает лишь, что
// отзывы придётся получить снова по gossip.
func (s *CRLStore) loadCache() {
	data, err := os.ReadFile(s.cachePath)
	if err != nil {
		return
	}

	var cache revokedCacheFile
	if err := json.Unmarshal(data, &cache); err != nil {
		log.Printf("[CRL] кэш отзывов повреждён, игнорируем: %v", err)
		return
	}

	for _, entry := range cache.Entries {
		serial := new(big.Int)
		if _, ok := serial.SetString(entry.Serial, 10); !ok {
			continue
		}
		key := serialKey(serial)

		if _, exists := s.revoked[key]; exists {
			continue
		}

		s.revoked[key] = revokedCert{
			SerialNumber: serial,
			RevokedAt:    time.Unix(entry.At, 0),
			Reason:       entry.Reason,
		}
	}

	// Номер CRL тоже должен пережить перезапуск: иначе после ребута версия
	// снова станет 0, и соседи с реальными номерами покажутся «новее».
	if cache.Number > s.number {
		s.number = cache.Number
	}
}

// LoadCRLStore загружает CRL с диска, при необходимости конвертируя
// устаревший бинарный формат.
//
// Конвертация нужна один раз: файлы, записанные прошлыми версиями, содержат
// хеши от CN и не имеют номера версии. Такие CRL нечем подписывать и не по
// чему сравнивать, поэтому они переводятся в x509-формат с сохранением
// исходника рядом — отзывы не теряются.
func LoadCRLStore(crlPath, caCertPath, caKeyPath string) (*CRLStore, error) {
	store := &CRLStore{
		revoked:   make(map[string]revokedCert),
		diskPath:  crlPath,
		cachePath: crlCachePath(crlPath),
	}

	// Ключ и сертификат CA нужны для подписи. Их отсутствие не повод
	// отказываться: обычному маячку CRL достаточно читать, а полученные
	// по gossip отзывы он хранит в локальном кэше.
	if caCert, err := LoadCACert(caCertPath); err == nil {
		store.caCert = caCert
	}
	if caKey, err := LoadCAKey(caKeyPath); err == nil {
		store.caKey = caKey
	}

	if err := store.loadFromDisk(); err != nil {
		return store, err
	}

	// Кэш подмешивается после CRL: подписанный список CA имеет приоритет.
	store.loadCache()

	return store, nil
}

// crlCachePath возвращает путь к локальному кэшу отзывов рядом с CRL.
func crlCachePath(crlPath string) string {
	return filepath.Join(filepath.Dir(crlPath), revokedCacheFileName)
}

// loadFromDisk читает CRL, конвертируя старый формат при необходимости.
func (s *CRLStore) loadFromDisk() error {
	data, err := os.ReadFile(s.diskPath)
	if err != nil {
		if os.IsNotExist(err) {
			// CRL ещё не выпускался — это нормальное состояние.
			return nil
		}
		return fmt.Errorf("чтение CRL %s: %w", s.diskPath, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("CRL %s: не удалось декодировать PEM", s.diskPath)
	}

	// Сначала пробуем стандартный x509-парсер.
	if list, err := x509.ParseRevocationList(block.Bytes); err == nil {
		// Подпись проверяется ДО принятия записей. Без этой проверки CRL,
		// подписанный посторонним CA, применялся бы как настоящий: любой,
		// кто сумел положить файл в каталог, мог отозвать чужие сертификаты.
		if s.caCert != nil {
			if err := list.CheckSignatureFrom(s.caCert); err != nil {
				return fmt.Errorf("CRL %s подписан не нашим CA: %w", s.diskPath, err)
			}
		}
		s.adoptRevocationList(list)
		return nil
	}

	// Не x509 — вероятно, старый собственный формат.
	return s.convertLegacy(block.Bytes)
}

// adoptRevocationList загружает записи из разобранного CRL.
func (s *CRLStore) adoptRevocationList(list *x509.RevocationList) {
	s.number = list.Number.Uint64()
	s.thisUpdate = list.ThisUpdate
	s.nextUpdate = list.NextUpdate

	s.revoked = make(map[string]revokedCert, len(list.RevokedCertificateEntries))

	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber == nil {
			continue
		}
		key := serialKey(entry.SerialNumber)
		s.revoked[key] = revokedCert{
			SerialNumber: entry.SerialNumber,
			RevokedAt:    entry.RevocationTime,
			Reason:       uint8(entry.ReasonCode),
		}
	}
}

// convertLegacy переводит старый бинарный CRL в формат x509.
//
// Старый формат хранил 16-байтовый хеш от CN, а не серийник. Восстановить
// серийники по нему невозможно — потеряна информация. Поэтому каждый хеш
// сопоставляется с сертификатами на диске: если соответствующий сертификат
// найден, берётся его настоящий серийник. Не найденные хеши сохраняются как
// есть — иначе часть отзывов молча исчезла бы, и отозванный узел продолжил бы
// работать в сети.
func (s *CRLStore) convertLegacy(der []byte) error {
	entries, err := deserializeLegacyCRL(der)
	if err != nil {
		return fmt.Errorf("CRL %s: ни x509, ни legacy-формат не разобрался: %w", s.diskPath, err)
	}

	serialByHash, err := resolveLegacyHashes(s.diskPath)
	if err != nil {
		return err
	}

	unresolved := 0
	for _, entry := range entries {
		// Хеш от CN однозначно соответствует одному сертификату на диске
		// (в пределах одной выдачи), поэтому восстановить серийник можно.
		certPath, ok := serialByHash[entry.SerialHash]
		if !ok {
			unresolved++
			continue
		}

		cert, err := ParseCertificateFile(certPath)
		if err != nil {
			unresolved++
			continue
		}

		s.revoked[serialKey(cert.SerialNumber)] = revokedCert{
			SerialNumber: cert.SerialNumber,
			RevokedAt:    time.Unix(entry.RevokedAt, 0),
			Reason:       entry.Reason,
		}
	}

	// Сохраняем оригинал, чтобы оператор мог разобраться с нерезолвенными.
	backup := s.diskPath + crlLegacyBackupSuffix
	if err := os.WriteFile(backup, pem.EncodeToMemory(&pem.Block{Type: "LEGACY CRL", Bytes: der}), 0600); err != nil {
		return fmt.Errorf("сохранение резервной копии старого CRL: %w", err)
	}

	fmt.Printf("[CRL] сконвертирован старый формат: записей %d, восстановлено серийников %d\n",
		len(entries), len(entries)-unresolved)
	if unresolved > 0 {
		fmt.Printf("[CRL] ВНИМАНИЕ: %d записей не удалось сопоставить с сертификатами "+
			"на диске и они отброшены. Оригинал сохранён в %s.\n"+
			"[CRL] Восстановите файлы сертификатов и повторите запуск, "+
			"либо отзовите эти узлы заново.\n", unresolved, backup)
	}

	// Перезаписываем CRL новым форматом с подписью CA.
	return s.Save()
}

// resolveLegacyHashes строит соответствие «хеш от CN -> путь к сертификату».
func resolveLegacyHashes(crlPath string) (map[[16]byte]string, error) {
	dataDir := filepath.Dir(filepath.Dir(crlPath))

	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return nil, fmt.Errorf("чтение каталога данных: %w", err)
	}

	out := make(map[[16]byte]string)

	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "ca" || entry.Name() == "peers" {
			continue
		}

		certPath := filepath.Join(dataDir, entry.Name(), "cert.pem")
		certData, err := os.ReadFile(certPath)
		if err != nil {
			continue
		}

		cert, err := ParseCertificatePEM(certData)
		if err != nil {
			continue
		}

		out[ComputeSerialHash(cert)] = certPath
	}

	return out, nil
}

// ParseCertificateFile читает и разбирает сертификат из файла.
func ParseCertificateFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("чтение сертификата %s: %w", path, err)
	}
	return ParseCertificatePEM(data)
}

// Revoke добавляет сертификат в CRL.
//
// Номер CRL увеличивается на каждый новый отзыв: он и есть «версия» списка,
// по которой узлы сравнивают CRL. Прежний счётчик жил только в памяти и
// обнулялся при каждом запуске, поэтому версии у разных узлов случайно
// совпадали, а gossip их отбрасывал.
func (s *CRLStore) Revoke(serial *big.Int, reason uint8) error {
	if serial == nil {
		return fmt.Errorf("серийный номер не задан")
	}

	key := serialKey(serial)
	if _, already := s.revoked[key]; !already {
		s.number++
	}

	s.revoked[key] = revokedCert{
		SerialNumber: serial,
		RevokedAt:    time.Now(),
		Reason:       reason,
	}

	// Кэш пишется всегда: он переживает перезапуск даже там, где подписать
	// CRL нечем (обычный маячок).
	if err := s.saveCache(); err != nil {
		log.Printf("[CRL] кэш отзывов не сохранён: %v", err)
	}

	return s.Save()
}

// IsRevoked проверяет, отозван ли сертификат с данным серийным номером.
func (s *CRLStore) IsRevoked(serial *big.Int) bool {
	if serial == nil {
		return false
	}
	_, ok := s.revoked[serialKey(serial)]
	return ok
}

// Entries возвращает отсортированные копии отзывов — для вывода и gossip.
func (s *CRLStore) Entries() []revokedCert {
	out := make([]revokedCert, 0, len(s.revoked))
	for _, e := range s.revoked {
		out = append(out, e)
	}

	// Стабильный порядок: иначе один и тот же CRL давал бы разные байты
	// при каждой сериализации.
	sort.Slice(out, func(i, j int) bool {
		return out[i].SerialNumber.Cmp(out[j].SerialNumber) < 0
	})

	return out
}

// Number возвращает номер CRL для сравнения версий.
func (s *CRLStore) Number() uint64 { return s.number }

// NextUpdate возвращает срок действия CRL.
func (s *CRLStore) NextUpdate() time.Time { return s.nextUpdate }

// SetNumber задаёт номер CRL — используется при загрузке gossip-обновления.
func (s *CRLStore) SetNumber(n uint64) { s.number = n }

// Merge применяет отзывы, полученные от соседа.
//
// Отзывы принимаются ВСЕГДА, независимо от версий отправителя: CRL только
// растёт, поэтому объединение безопасно. Прежняя проверка
// `senderVersion <= localVersion` отбрасывала всё у свежих узлов, у которых
// счётчик версий начинался с нуля при каждом запуске.
func (s *CRLStore) Merge(entries []revokedCert, senderNumber uint64) bool {
	if len(entries) == 0 {
		return false
	}

	changed := false

	for _, e := range entries {
		if e.SerialNumber == nil {
			continue
		}
		key := serialKey(e.SerialNumber)

		// Не понижаем время отзыва, если запись уже есть.
		if existing, ok := s.revoked[key]; ok {
			if existing.RevokedAt.After(e.RevokedAt) {
				continue
			}
			if existing.Reason == e.Reason && existing.RevokedAt.Equal(e.RevokedAt) {
				continue
			}
		}

		s.revoked[key] = e
		changed = true
	}

	if senderNumber > s.number {
		s.number = senderNumber
	}

	if !changed {
		return false
	}

	// Кэш — единственное, что переживёт перезапуск на узле без ключа CA,
	// поэтому пишется всегда, независимо от наличия подписи.
	if err := s.saveCache(); err != nil {
		log.Printf("[CRL] кэш отзывов не сохранён: %v", err)
	}

	return true
}

// Save сериализует CRL на диск, подписывая его ключом CA.
//
// Если ключа CA нет (узел читает, но не подписывает), CRL всё равно
// сохраняется — но без подписи такой файл повторно не прочитается как x509.
// В этом случае запись CRL на узле бессмысленна и отзыва нет.
func (s *CRLStore) Save() error {
	if s.caKey == nil || s.caCert == nil {
		return fmt.Errorf("невозможно сохранить CRL: не найден %s — подписывать CRL вправе "+
			"только узел с файлом ca/ca-key.pem, обычные маячки CRL только читают",
			s.missingCAPart())
	}

	// Продлеваем окно действия.
	s.thisUpdate = time.Now().Add(-5 * time.Minute)
	s.nextUpdate = s.thisUpdate.Add(DefaultCRLUpdateInterval)

	// Номер обязан быть ненулевым: CRLNumber = 0 невалиден по RFC 5280.
	if s.number == 0 {
		s.number = 1
	}

	tmpl := &x509.RevocationList{
		Number:                    new(big.Int).SetUint64(s.number),
		ThisUpdate:                s.thisUpdate,
		NextUpdate:                s.nextUpdate,
		RevokedCertificateEntries: make([]x509.RevocationListEntry, 0, len(s.revoked)),
	}

	for _, e := range s.Entries() {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   e.SerialNumber,
			RevocationTime: e.RevokedAt,
			ReasonCode:     int(e.Reason),
		})
	}

	der, err := x509.CreateRevocationList(rand.Reader, tmpl, s.caCert, s.caKey)
	if err != nil {
		return fmt.Errorf("подпись CRL: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: crlPEMType, Bytes: der})

	// Атомарная запись: сосед может читать CRL в этот момент.
	tmp := s.diskPath + ".tmp"
	if err := os.WriteFile(tmp, pemBytes, 0644); err != nil {
		return fmt.Errorf("запись временного CRL: %w", err)
	}
	if err := os.Rename(tmp, s.diskPath); err != nil {
		return fmt.Errorf("сохранение CRL: %w", err)
	}

	return nil
}

// deserializeLegacyCRL разбирает старый собственный бинарный формат CRL.
//
//	[4 байта count] + count * [16(хеш) + 8(время) + 1(причина)]
//
// Существует только для разовой конвертации файлов, записанных прошлыми
// версиями. Новые CRL всегда в формате x509.
func deserializeLegacyCRL(data []byte) ([]legacyCRLEntry, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("старый CRL слишком короткий")
	}

	count := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if count < 0 || len(data) < 4+count*25 {
		return nil, fmt.Errorf("старый CRL: неверная длина (ожидается %d, получено %d)", 4+count*25, len(data))
	}

	entries := make([]legacyCRLEntry, count)

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

// legacyCRLEntry — запись старого формата CRL.
type legacyCRLEntry struct {
	// SerialHash — SHA-256 от RawSubject+RawIssuer. Серийника здесь нет,
	// поэтому при конвертации он восстанавливается по сертификату на диске.
	SerialHash [16]byte
	RevokedAt  int64
	Reason     uint8
}

// missingCAPart возвращает читаемое имя отсутствующей части CA.
func (s *CRLStore) missingCAPart() string {
	switch {
	case (s.caCert == nil) && (s.caKey == nil):
		return "ни сертификат CA, ни ключ CA"
	case s.caCert == nil:
		return "сертификат CA"
	default:
		return "ключ CA"
	}
}

// serialKey возвращает строковый ключ для карты отзывов.
func serialKey(serial *big.Int) string {
	return serial.String()
}
