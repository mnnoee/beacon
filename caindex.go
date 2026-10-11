package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// caIndexFile — имя файла индекса выданных сертификатов внутри ca/.
const caIndexFile = "index.json"

// caIndexVersion — формат файла индекса. Повышается при несовместимых
// изменениях структуры.
const caIndexVersion = 1

// CAIndexEntry — запись об одном выданном узле.
type CAIndexEntry struct {
	// Serial — серийный номер сертификата в виде строки.
	// Именно он является ключом отзыва (см. RevokeCertificate), а не хеш от CN:
	// хеш от CN одинаков для всех пере-выдач на одно имя и приводит к тому, что
	// отзыв старого сертификата убивает и новый.
	Serial string `json:"serial"`

	// NodeID — идентификатор узла (hex, 32 символа), производный от Ed25519-ключа.
	NodeID string `json:"node_id"`

	// IssuedAt — время выдачи в RFC3339.
	IssuedAt string `json:"issued_at"`
}

// CAIndex — реестр выданных сертификатов: CN → запись.
//
// Решает три задачи:
//  1. Запрет дублирующихся CN — иначе в сети появляется несколько сертификатов
//     с одинаковым именем, что ломает и отзыв, и сопоставление «имя → узел».
//  2. Пере-выдача ключа потерянного устройства: наличие записи отличает
//     пере-выдачу от опечатки при первом вводе имени.
//  3. Человекочитаемый список: пользователю больше не нужно вручную находить
//     серийный номер, чтобы отозвать сертификат.
type CAIndex struct {
	Version int                     `json:"version"`
	Nodes   map[string]CAIndexEntry `json:"nodes"`
}

// CAIndexPath возвращает путь к файлу индекса.
func CAIndexPath(dataDir string) string {
	return filepath.Join(dataDir, "ca", caIndexFile)
}

// LoadCAIndex загружает индекс с диска. Отсутствие файла — не ошибка:
// возвращается пустой индекс, готовый к записи.
func LoadCAIndex(dataDir string) (*CAIndex, error) {
	path := CAIndexPath(dataDir)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &CAIndex{Version: caIndexVersion, Nodes: map[string]CAIndexEntry{}}, nil
		}
		return nil, fmt.Errorf("чтение индекса CA: %w", err)
	}

	idx := &CAIndex{}
	if err := json.Unmarshal(data, idx); err != nil {
		return nil, fmt.Errorf("разбор индекса CA %s: %w", path, err)
	}

	if idx.Nodes == nil {
		idx.Nodes = map[string]CAIndexEntry{}
	}
	if idx.Version == 0 {
		idx.Version = caIndexVersion
	}

	return idx, nil
}

// SaveCAIndex сохраняет индекс на диск атомарно: сначала во временный файл,
// затем переименование. Так параллельный `ca list-trusted` никогда не прочитает
// наполовину записанный JSON.
func SaveCAIndex(dataDir string, idx *CAIndex) error {
	path := CAIndexPath(dataDir)

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("создание директории CA: %w", err)
	}

	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return fmt.Errorf("сериализация индекса CA: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("запись временного файла индекса: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("сохранение индекса CA: %w", err)
	}

	return nil
}

// Lookup возвращает запись по CN.
func (idx *CAIndex) Lookup(cn string) (CAIndexEntry, bool) {
	entry, ok := idx.Nodes[cn]
	return entry, ok
}

// Names возвращает отсортированный список CN — для стабильного вывода.
func (idx *CAIndex) Names() []string {
	names := make([]string, 0, len(idx.Nodes))
	for cn := range idx.Nodes {
		names = append(names, cn)
	}
	sort.Strings(names)
	return names
}

// NewEntry создаёт запись индекса для выданного сертификата.
func NewEntry(serial *big.Int, nodeID [16]byte) CAIndexEntry {
	return CAIndexEntry{
		Serial:   serial.String(),
		NodeID:   fmt.Sprintf("%X", nodeID),
		IssuedAt: time.Now().Format(time.RFC3339),
	}
}

// SerialNumber разбирает сохранённый серийный номер обратно в big.Int.
func (e CAIndexEntry) SerialNumber() (*big.Int, error) {
	n := new(big.Int)
	if _, ok := n.SetString(e.Serial, 10); !ok {
		return nil, fmt.Errorf("невалидный серийный номер в индексе CA: %q", e.Serial)
	}
	return n, nil
}

// archiveCertPath возвращает путь архива отозываемых сертификатов для узла.
func archiveCertPath(dataDir, nodeName string) string {
	return filepath.Join(dataDir, "ca", "replaced", nodeName)
}

// ArchiveCertIfPresent сохраняет текущий сертификат узла перед пере-выдачей.
//
// Зачем: пере-выдача перезаписывает beacon-<имя>/cert.pem, после чего прежний
// сертификат исчезает с диска. Но именно его серийник мы показываем
// пользователю для отзыва, и искать его по `ca revoke-beacon -serial` больше
// негде — findCertBySerial сканирует живые каталоги узлов. Без архива
// предупреждение о пере-выдаче было бы бесполезным: отозвать старый
// сертификат было бы физически нечем.
func ArchiveCertIfPresent(dataDir, nodeName string) error {
	certPath := filepath.Join(dataDir, nodeName, "cert.pem")

	data, err := os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("чтение текущего сертификата для архива: %w", err)
	}

	cert, err := ParseCertificatePEM(data)
	if err != nil {
		return fmt.Errorf("разбор текущего сертификата для архива: %w", err)
	}

	dir := archiveCertPath(dataDir, nodeName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("создание архива сертификатов: %w", err)
	}

	// Имя по серийнику: устойчиво к повторным пере-выдачам и читаемо.
	name := fmt.Sprintf("%s.pem", cert.SerialNumber.String())
	dst := filepath.Join(dir, name)

	if err := os.WriteFile(dst, data, 0644); err != nil {
		return fmt.Errorf("сохранение сертификата в архив: %w", err)
	}

	return nil
}

// findCertBySerialInArchive ищет сертификат по серийному номеру среди
// архивированных (вытесненных пере-выдачей) сертификатов.
func findCertBySerialInArchive(dataDir string, serial *big.Int) (*x509.Certificate, error) {
	root := filepath.Join(dataDir, "ca", "replaced")

	if _, err := os.Stat(root); os.IsNotExist(err) {
		return nil, fmt.Errorf("архив заменённых сертификатов пуст")
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("чтение архива: %w", err)
	}

	for _, nodeDir := range entries {
		if !nodeDir.IsDir() {
			continue
		}

		files, err := os.ReadDir(filepath.Join(root, nodeDir.Name()))
		if err != nil {
			continue
		}

		for _, f := range files {
			if f.IsDir() || filepath.Ext(f.Name()) != ".pem" {
				continue
			}

			path := filepath.Join(root, nodeDir.Name(), f.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			cert, err := ParseCertificatePEM(data)
			if err != nil {
				continue
			}

			if cert.SerialNumber.Cmp(serial) == 0 {
				return cert, nil
			}
		}
	}

	return nil, fmt.Errorf("сертификат с серийным номером %s не найден в архиве %s", serial, root)
}
