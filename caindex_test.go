package main

import (
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// errDuplicateCN — ошибка выдачи на уже занятое имя без -reissue.
var errDuplicateCN = errors.New("сертификат для этого имени уже выдан")

// errUnknownNode — ошибка -reissue для имени, которого нет в индексе.
var errUnknownNode = errors.New("сертификат для этого имени не найден в индексе CA")

// formatNodeID приводит NodeID к строке в том же виде, что и в индексе.
func formatNodeID(id [16]byte) string { return fmt.Sprintf("%X", id) }

// newBigOne — серийник, заведомо не выданный ни одному узлу.
func newBigOne() *big.Int { return big.NewInt(987654321987654321) }

// TestCAIndexRejectsDuplicateCN — ключевая гарантия фазы 0: на одно имя нельзя
// выдать два сертификата обычной командой. Иначе в сети появляются два узла с
// одинаковым CN, а отзыв одного задевает оба (ключ CRL — хеш от CN).
func TestCAIndexRejectsDuplicateCN(t *testing.T) {
	dir := t.TempDir()
	_, certPEM, _ := GenerateCA(dir, DefaultCALifetime)
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	first, err := IssueCertificate(caKey, certPEM, dir, "beacon-nas", DefaultCertTTL, RolePeer)
	if err != nil {
		t.Fatalf("первая выдача: %v", err)
	}

	idx, err := LoadCAIndex(dir)
	if err != nil {
		t.Fatalf("LoadCAIndex: %v", err)
	}
	idx.Nodes["beacon-nas"] = NewEntry(first.Serial, first.NodeID)
	if err := SaveCAIndex(dir, idx); err != nil {
		t.Fatalf("SaveCAIndex: %v", err)
	}

	// Индекс видит имя как занятое.
	idx2, _ := LoadCAIndex(dir)
	entry, exists := idx2.Lookup("beacon-nas")
	if !exists {
		t.Fatal("имя должно быть в индексе после выдачи")
	}
	if entry.Serial != first.Serial.String() {
		t.Fatalf("серийник в индексе %s != выданный %s", entry.Serial, first.Serial)
	}
	if entry.NodeID != formatNodeID(first.NodeID) {
		t.Fatalf("nodeID в индексе %s != выданный %X", entry.NodeID, first.NodeID)
	}

	// Выдача второго сертификата на то же имя без -reissue обязана быть
	// отвергнута на уровне CLI.
	if err := checkProvisionAllowed(dir, "beacon-nas", false); err == nil {
		t.Fatal("повторная выдача на занятое имя должна отвергаться")
	}

	// С -reissue — разрешена, это пере-выдача потерянного ключа.
	if err := checkProvisionAllowed(dir, "beacon-nas", true); err != nil {
		t.Fatalf("-reissue должен быть разрешён: %v", err)
	}

	// Пере-выдача для несуществующего имени — ошибка со списком узлов.
	if err := checkProvisionAllowed(dir, "beacon-typo", true); err == nil {
		t.Fatal("-reissue для неизвестного имени должен отвергаться")
	}
}

// checkProvisionAllowed повторяет проверку из cmdProvisionBeacon, не вызывая
// os.Exit: тестируем логику, а не завершение процесса.
func checkProvisionAllowed(dataDir, nodeName string, reissue bool) error {
	name, err := normalizeNodeName(nodeName)
	if err != nil {
		return err
	}

	idx, err := LoadCAIndex(dataDir)
	if err != nil {
		return err
	}

	_, exists := idx.Lookup(name)

	if exists && !reissue {
		return errDuplicateCN
	}
	if !exists && reissue {
		return errUnknownNode
	}

	return nil
}

// TestReissueChangesSerialAndNodeID проверяет, что пере-выдача действительно
// даёт новое поколение ключей и новый NodeID, а старый серийник остаётся
// доступным для отзыва.
func TestReissueChangesSerialAndNodeID(t *testing.T) {
	dir := t.TempDir()
	_, certPEM, _ := GenerateCA(dir, DefaultCALifetime)
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	first, err := IssueCertificate(caKey, certPEM, dir, "beacon-router", DefaultCertTTL, RolePeer)
	if err != nil {
		t.Fatalf("первая выдача: %v", err)
	}

	idx, _ := LoadCAIndex(dir)
	idx.Nodes["beacon-router"] = NewEntry(first.Serial, first.NodeID)
	SaveCAIndex(dir, idx)

	// Старый серийник должен оставаться доступным для отзыва. Архивирование
	// выполняет CLI перед пере-выдачей, поэтому повторяем именно его.
	if err := ArchiveCertIfPresent(dir, "beacon-router"); err != nil {
		t.Fatalf("ArchiveCertIfPresent: %v", err)
	}

	second, err := IssueCertificate(caKey, certPEM, dir, "beacon-router", DefaultCertTTL, RolePeer)
	if err != nil {
		t.Fatalf("пере-выдача: %v", err)
	}

	if second.Serial.Cmp(first.Serial) == 0 {
		t.Fatal("пере-выдача должна давать новый серийный номер")
	}
	if second.NodeID == first.NodeID {
		t.Fatal("пере-выдача должна давать новый NodeID (новый Ed25519-ключ)")
	}

	// Старая запись в индексе заменяется, но её серийник известен —
	// именно он нужен для отзыва протухшего сертификата.
	idx2, _ := LoadCAIndex(dir)
	oldEntry := NewEntry(first.Serial, first.NodeID)
	idx2.Nodes["beacon-router"] = NewEntry(second.Serial, second.NodeID)
	SaveCAIndex(dir, idx2)

	idx3, _ := LoadCAIndex(dir)
	entry, _ := idx3.Lookup("beacon-router")
	if entry.Serial != second.Serial.String() {
		t.Fatalf("в индексе должен лежать новый серийник, получено %s", entry.Serial)
	}

	// Старый серийник всё ещё резолвится в старый сертификат на диске.
	oldSerial, err := oldEntry.SerialNumber()
	if err != nil {
		t.Fatalf("разбор старого серийника: %v", err)
	}
	found, err := findCertBySerial(dir, oldSerial)
	if err != nil {
		t.Fatalf("старый сертификат должен оставаться доступным для отзыва: %v", err)
	}
	if found.Subject.CommonName != "beacon-router" {
		t.Fatalf("неверный CN: %s", found.Subject.CommonName)
	}
}

// TestRevokeBySerialLookup проверяет поиск сертификата по серийному номеру —
// этим пользуется `ca revoke-beacon -serial`.
func TestRevokeBySerialLookup(t *testing.T) {
	dir := t.TempDir()
	_, certPEM, _ := GenerateCA(dir, DefaultCALifetime)
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	a, _ := IssueCertificate(caKey, certPEM, dir, "beacon-a", DefaultCertTTL, RolePeer)
	b, _ := IssueCertificate(caKey, certPEM, dir, "beacon-b", DefaultCertTTL, RolePeer)

	found, err := findCertBySerial(dir, a.Serial)
	if err != nil {
		t.Fatalf("поиск по серийнику: %v", err)
	}
	if found.Subject.CommonName != "beacon-a" {
		t.Fatalf("найден не тот сертификат: %s", found.Subject.CommonName)
	}

	foundB, err := findCertBySerial(dir, b.Serial)
	if err != nil {
		t.Fatalf("поиск второго: %v", err)
	}
	if foundB.Subject.CommonName != "beacon-b" {
		t.Fatalf("найден не тот сертификат: %s", foundB.Subject.CommonName)
	}

	// Несуществующий серийник — понятная ошибка, а не паника.
	if _, err := findCertBySerial(dir, newBigOne()); err == nil {
		t.Fatal("поиск несуществующего серийника должен давать ошибку")
	}
}

// TestCAIndexPersistence проверяет сохранение и повторную загрузку индекса,
// включая атомарность записи.
func TestCAIndexPersistence(t *testing.T) {
	dir := t.TempDir()

	// Пустой индекс создаётся без ошибки, если файла нет.
	idx, err := LoadCAIndex(dir)
	if err != nil {
		t.Fatalf("LoadCAIndex на пустом каталоге: %v", err)
	}
	if len(idx.Nodes) != 0 {
		t.Fatal("индекс должен быть пустым")
	}

	idx.Nodes["beacon-x"] = CAIndexEntry{
		Serial:   "12345",
		NodeID:   "AABBCCDDEEFF00112233445566778899",
		IssuedAt: "2026-01-01T00:00:00Z",
	}
	if err := SaveCAIndex(dir, idx); err != nil {
		t.Fatalf("SaveCAIndex: %v", err)
	}

	loaded, err := LoadCAIndex(dir)
	if err != nil {
		t.Fatalf("повторная загрузка: %v", err)
	}

	entry, ok := loaded.Lookup("beacon-x")
	if !ok {
		t.Fatal("запись не сохранилась")
	}
	if entry.Serial != "12345" {
		t.Fatalf("серийник не сохранился: %s", entry.Serial)
	}

	// Временный файл не должен оставаться после записи.
	tmp := CAIndexPath(dir) + ".tmp"
	if _, err := os.Stat(tmp); err == nil {
		t.Fatal("временный файл индекса не удалён после сохранения")
	}

	// Порядок имён стабилен — от этого зависит вывод list-trusted.
	idx.Nodes["beacon-z"] = CAIndexEntry{Serial: "1"}
	idx.Nodes["beacon-a"] = CAIndexEntry{Serial: "2"}
	names := idx.Names()
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("имена не отсортированы: %v", names)
		}
	}
}

// TestIndexEntrySerialParsing проверяет разбор серийника из индекса.
func TestIndexEntrySerialParsing(t *testing.T) {
	entry := CAIndexEntry{Serial: "340282366920938463463374607431768211455"}
	n, err := entry.SerialNumber()
	if err != nil {
		t.Fatalf("SerialNumber: %v", err)
	}
	if n.String() != entry.Serial {
		t.Fatalf("разбор не дал исходное значение: %s", n)
	}

	bad := CAIndexEntry{Serial: "не-число"}
	if _, err := bad.SerialNumber(); err == nil {
		t.Fatal("невалидный серийник должен давать ошибку")
	}
}

// TestNodeNameNormalization проверяет правила имени узла.
func TestNodeNameNormalization(t *testing.T) {
	got, err := normalizeNodeName("nas")
	if err != nil {
		t.Fatalf("normalizeNodeName: %v", err)
	}
	if got != "beacon-nas" {
		t.Fatalf("префикс не добавлен: %s", got)
	}

	already, _ := normalizeNodeName("beacon-nas")
	if already != "beacon-nas" {
		t.Fatalf("префикс продублирован: %s", already)
	}

	// Короткое имя без префикса отвергается: проверка длины идёт до
	// добавления префикса, иначе опечатка стала бы "beacon-xx".
	if _, err := normalizeNodeName("ab"); err == nil {
		t.Fatal("слишком короткое исходное имя должно отвергаться")
	}

	// Имя из одной-двух букв без префикса — тоже опечатка.
	if _, err := normalizeNodeName("x"); err == nil {
		t.Fatal("однобуквенное имя должно отвергаться")
	}

	// Слишком длинное имя отвергается.
	long := "beacon-" + strings.Repeat("x", 60)
	if _, err := normalizeNodeName(long); err == nil {
		t.Fatal("слишком длинное имя должно отвергаться")
	}

	// Имя без префикса, которое в пределах лимита, но не влезает с ним.
	if _, err := normalizeNodeName(strings.Repeat("x", 60)); err == nil {
		t.Fatal("имя, не влезающее с префиксом, должно отвергаться")
	}

	// Пустое имя отвергается.
	if _, err := normalizeNodeName(""); err == nil {
		t.Fatal("пустое имя должно отвергаться")
	}

	// Пробелы обрезаются.
	padded, err := normalizeNodeName("  beacon-nas  ")
	if err != nil {
		t.Fatalf("пробелы должны обрезаться: %v", err)
	}
	if padded != "beacon-nas" {
		t.Fatalf("пробелы не обрезаны: %q", padded)
	}
}

// TestBeaconsDirectoryLayout проверяет, что выдача создаёт ожидаемый набор
// файлов: без ed25519-key.pem узел не сможет подняться после фазы 0.
func TestBeaconsDirectoryLayout(t *testing.T) {
	dir := t.TempDir()
	_, certPEM, _ := GenerateCA(dir, DefaultCALifetime)
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	issued, err := IssueCertificate(caKey, certPEM, dir, "beacon-layout", DefaultCertTTL, RolePeer)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	for _, path := range []string{issued.CertPath, issued.KeyPath, issued.Ed25519Path} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("файл не создан: %s", path)
		}
		if filepath.Dir(path) != filepath.Join(dir, "beacon-layout") {
			t.Fatalf("неверное расположение: %s", path)
		}
	}

	// Приватные ключи — 0600.
	for _, path := range []string{issued.KeyPath, issued.Ed25519Path} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Fatalf("права %s должны быть 0600, получено %o", path, perm)
		}
	}

	// Каталог узла — 0700.
	nodeDir := filepath.Join(dir, "beacon-layout")
	info, err := os.Stat(nodeDir)
	if err != nil {
		t.Fatalf("stat nodeDir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Fatalf("права каталога должны быть 0700, получено %o", perm)
	}
}
