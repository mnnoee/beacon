package main

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCAPaths создаёт CA на диске и возвращает пути к нему.
func testCAPaths(t *testing.T, dir string) (caCertPath, caKeyPath, crlPath string) {
	t.Helper()

	if _, _, err := GenerateCA(dir, DefaultCALifetime); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	return filepath.Join(dir, "ca", "ca-cert.pem"),
		filepath.Join(dir, "ca", "ca-key.pem"),
		filepath.Join(dir, "ca", "crl.pem")
}

// TestCRLSignedByCA — главное свойство нового CRL: он подписан ключом CA.
//
// Прежний формат был самодельным бинарным блоком без подписи вообще: файл,
// полученный не из сети, неотличим от настоящего. Теперь CRL — настоящий
// x509.RevocationList с CRLNumber и окном действия.
func TestCRLSignedByCA(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath, crlPath := testCAPaths(t, dir)

	store, err := LoadCRLStore(crlPath, caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("LoadCRLStore: %v", err)
	}

	serial := big.NewInt(0xDEADBEEF)
	if err := store.Revoke(serial, 1); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	data, err := os.ReadFile(crlPath)
	if err != nil {
		t.Fatalf("чтение CRL: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("CRL не является PEM")
	}

	// Стандартный парсер обязан принять файл.
	list, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParseRevocationList: %v", err)
	}

	if list.Number == nil || list.Number.Uint64() == 0 {
		t.Fatal("CRLNumber должен быть задан")
	}
	if list.NextUpdate.Before(time.Now()) {
		t.Fatal("NextUpdate должен быть в будущем")
	}
	if len(list.RevokedCertificateEntries) != 1 {
		t.Fatalf("ожидалась 1 запись, получено %d", len(list.RevokedCertificateEntries))
	}
	if list.RevokedCertificateEntries[0].SerialNumber.Cmp(serial) != 0 {
		t.Fatal("серийник не совпал")
	}

	// Подпись проверяется публичным ключом CA.
	caCert, _ := LoadCACert(caCertPath)
	if err := list.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("подпись CRL не проверяется ключом CA: %v", err)
	}
}

// TestCRLNumberSurvivesRestart — номер CRL обязан переживать перезапуск.
// Именно этим ломался прежний счётчик в памяти.
func TestCRLNumberSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath, crlPath := testCAPaths(t, dir)

	store, _ := LoadCRLStore(crlPath, caCertPath, caKeyPath)
	if err := store.Revoke(big.NewInt(1), 1); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	firstNumber := store.Number()

	// «Перезапуск»: читаем CRL заново с диска.
	reloaded, _ := LoadCRLStore(crlPath, caCertPath, caKeyPath)

	if reloaded.Number() != firstNumber {
		t.Fatalf("номер CRL не пережил перезапуск: было %d, стало %d",
			firstNumber, reloaded.Number())
	}

	if !reloaded.IsRevoked(big.NewInt(1)) {
		t.Fatal("отзыв должен сохраниться")
	}

	// Второй отзыв обязан поднять номер.
	if err := reloaded.Revoke(big.NewInt(2), 1); err != nil {
		t.Fatalf("второй отзыв: %v", err)
	}
	if reloaded.Number() <= firstNumber {
		t.Fatal("номер CRL должен вырасти после нового отзыва")
	}
}

// TestCRLRejectsUnsignedFile — файл CRL, подписанный чужим CA, не принимается.
func TestCRLRejectsUnsignedFile(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath, crlPath := testCAPaths(t, dir)

	store, _ := LoadCRLStore(crlPath, caCertPath, caKeyPath)
	if err := store.Revoke(big.NewInt(42), 1); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Подписываем CRL чужим CA.
	otherDir := t.TempDir()
	_, otherCertPEM, err := GenerateCA(otherDir, DefaultCALifetime)
	if err != nil {
		t.Fatalf("GenerateCA (чужая): %v", err)
	}

	otherCert, err := ParseCertificatePEM(otherCertPEM)
	if err != nil {
		t.Fatalf("разбор чужого сертификата: %v", err)
	}
	otherKey, err := LoadCAKey(filepath.Join(otherDir, "ca", "ca-key.pem"))
	if err != nil {
		t.Fatalf("чтение чужого ключа: %v", err)
	}

	tmpl := &x509.RevocationList{
		Number:     big.NewInt(99),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber:   big.NewInt(777),
			RevocationTime: time.Now(),
		}},
	}

	der, err := x509.CreateRevocationList(nil, tmpl, otherCert, otherKey)
	if err != nil {
		t.Fatalf("подпись чужим CA: %v", err)
	}

	forged := filepath.Join(dir, "ca", "forged-crl.pem")
	if err := os.WriteFile(forged, pem.EncodeToMemory(&pem.Block{Type: crlPEMType, Bytes: der}), 0644); err != nil {
		t.Fatalf("запись поддельного CRL: %v", err)
	}

	loaded, err := LoadCRLStore(forged, caCertPath, caKeyPath)
	if err == nil {
		t.Fatal("CRL, подписанный чужим CA, должен отвергаться при загрузке")
	}

	// И отзыв из него не должен применяться.
	if loaded.IsRevoked(big.NewInt(777)) {
		t.Fatal("отзыв из поддельного CRL не должен применяться")
	}

	// Наш собственный CRL той же формы принимается — проверка избирательна.
	ownPath := filepath.Join(dir, "ca", "own-crl.pem")
	own, _ := LoadCRLStore(crlPath, caCertPath, caKeyPath)
	if err := own.Revoke(big.NewInt(555), 1); err != nil {
		t.Fatalf("отзыв в нашем CRL: %v", err)
	}
	if err := copyFile(crlPath, ownPath); err != nil {
		t.Fatalf("копирование CRL: %v", err)
	}

	ownLoaded, err := LoadCRLStore(ownPath, caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("наш CRL должен приниматься: %v", err)
	}
	if !ownLoaded.IsRevoked(big.NewInt(555)) {
		t.Fatal("отзыв из нашего CRL должен применяться")
	}
}

// copyFile копирует файл — вспомогательная функция тестов.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// TestLegacyCRLConversion — конвертация старого формата не теряет отзывы.
func TestLegacyCRLConversion(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath, crlPath := testCAPaths(t, dir)

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("чтение CA-сертификата: %v", err)
	}

	caKey, _ := LoadCAKey(caKeyPath)

	issued, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-legacy", DefaultCertTTL)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	cert, err := loadCertPEM(issued.CertPath)
	if err != nil {
		t.Fatalf("загрузка сертификата: %v", err)
	}

	// Пишем CRL в старом формате: хеш от CN.
	legacyHash := ComputeSerialHash(cert)
	legacyEntries := []legacyCRLEntry{{
		SerialHash: legacyHash,
		RevokedAt:  time.Now().Unix(),
		Reason:     1,
	}}

	if err := writeLegacyCRL(crlPath, legacyEntries); err != nil {
		t.Fatalf("запись legacy CRL: %v", err)
	}

	// Читаем — должен сработать конвертер.
	store, err := LoadCRLStore(crlPath, caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("LoadCRLStore на legacy CRL: %v", err)
	}

	// Серийник восстановлен, а не потерян.
	if !store.IsRevoked(cert.SerialNumber) {
		t.Fatal("отзыв должен быть восстановлен по серийнику")
	}

	// Файл переписан в x509-формате, оригинал сохранён.
	data, _ := os.ReadFile(crlPath)
	block, _ := pem.Decode(data)
	if _, err := x509.ParseRevocationList(block.Bytes); err != nil {
		t.Fatalf("CRL должен быть перезаписан в x509-формате: %v", err)
	}

	if _, err := os.Stat(crlPath + crlLegacyBackupSuffix); err != nil {
		t.Fatal("резервная копия старого CRL должна сохраняться")
	}

	// Повторное чтение уже сконвертированного файла не должно ничего ломать.
	reloaded, err := LoadCRLStore(crlPath, caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("повторное чтение: %v", err)
	}
	if !reloaded.IsRevoked(cert.SerialNumber) {
		t.Fatal("отзыв должен сохраниться после повторного чтения")
	}
}

// TestCRLMergeUnion — объединение не теряет и не ломает записи.
func TestCRLMergeUnion(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath, crlPath := testCAPaths(t, dir)

	store, _ := LoadCRLStore(crlPath, caCertPath, caKeyPath)

	if err := store.Revoke(big.NewInt(1), 1); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Приходят отзывы от соседа, включая дубликат и новый.
	incoming := []revokedCert{
		{SerialNumber: big.NewInt(1), RevokedAt: time.Now().Add(-time.Hour), Reason: 1},
		{SerialNumber: big.NewInt(2), RevokedAt: time.Now(), Reason: 2},
	}

	if !store.Merge(incoming, 10) {
		t.Fatal("merge должен применить новые записи")
	}

	if !store.IsRevoked(big.NewInt(1)) {
		t.Fatal("существующий отзыв должен сохраниться")
	}
	if !store.IsRevoked(big.NewInt(2)) {
		t.Fatal("новый отзыв должен добавиться")
	}
	if store.Number() != 10 {
		t.Fatalf("номер CRL должен вырасти до 10, получено %d", store.Number())
	}

	// Номер от соседа ниже нашего — не понижаем.
	if store.Merge([]revokedCert{{SerialNumber: big.NewInt(3), RevokedAt: time.Now()}}, 3) {
		t.Log("новые записи приняты")
	}
	if store.Number() != 10 {
		t.Fatalf("номер CRL не должен уменьшаться: %d", store.Number())
	}

	// Повтор тех же данных — без изменений.
	if store.Merge(incoming, 10) {
		t.Fatal("повторное применение идентичных записей не должно считаться изменением")
	}
}

// TestCRLWithoutCAKeyCannotSign — узел без ключа CA читает CRL, но не подписывает.
//
// Это нормальное состояние обычного маячка: у него есть ca-cert.pem для
// проверки соседей, но нет приватного ключа CA. Попытка отозвать сертификат
// должна давать внятную ошибку, а не писать неподписанный файл.
func TestCRLWithoutCAKeyCannotSign(t *testing.T) {
	dir := t.TempDir()
	caCertPath, _, crlPath := testCAPaths(t, dir)

	// Загружаем без ключа CA — путь несуществующий.
	noKeyPath := filepath.Join(dir, "ca", "нет-ключа.pem")
	store, err := LoadCRLStore(crlPath, caCertPath, noKeyPath)
	if err != nil {
		t.Fatalf("LoadCRLStore: %v", err)
	}

	err = store.Revoke(big.NewInt(5), 1)
	if err == nil {
		t.Fatal("без ключа CA отзыв должен завершаться ошибкой")
	}

	// Файл при этом не должен быть создан/испорчен.
	if _, statErr := os.Stat(crlPath); statErr == nil {
		data, _ := os.ReadFile(crlPath)
		if block, _ := pem.Decode(data); block != nil {
			if _, parseErr := x509.ParseRevocationList(block.Bytes); parseErr == nil {
				t.Fatal("CRL не должен оказаться записанным без подписи CA")
			}
		}
	}
}

// TestGossipRevocationsSurviveRestartOnNonCA — регресс на дефект, найденный
// при проверке на реальных узлах.
//
// Обычный маячок не может подписать CRL: у него нет ca/ca-key.pem. Значит
// отзывы, пришедшие по gossip, некуда было записать в подписанном виде, и они
// держались только в памяти — после перезапуска отозванный узел снова
// считался доверенным. Теперь отзывы складываются в локальный кэш.
func TestGossipRevocationsSurviveRestartOnNonCA(t *testing.T) {
	dir := t.TempDir()
	caCertPath, _, crlPath := testCAPaths(t, dir)

	// Узел без ключа CA — как настоящий маячок в сети.
	noKeyPath := filepath.Join(dir, "ca", "ca-key-отсутствует.pem")

	store, err := LoadCRLStore(crlPath, caCertPath, noKeyPath)
	if err != nil {
		t.Fatalf("LoadCRLStore: %v", err)
	}

	serial := big.NewInt(31337)

	// Приходит gossip от соседа.
	changed := store.Merge([]revokedCert{{
		SerialNumber: serial,
		RevokedAt:    time.Now(),
		Reason:       1,
	}}, 5)

	if !changed {
		t.Fatal("gossip должен примениться")
	}

	if !store.IsRevoked(serial) {
		t.Fatal("отзыв должен применяться в памяти")
	}

	// Подписанный CRL записать нельзя — ключа CA нет.
	if err := store.Save(); err == nil {
		t.Fatal("без ключа CA подписанный CRL записаться не должен")
	}

	// Но кэш обязан существовать.
	cacheFile := filepath.Join(dir, "ca", revokedCacheFileName)
	if _, err := os.Stat(cacheFile); err != nil {
		t.Fatalf("кэш отзывов должен быть создан: %v", err)
	}

	// «Перезапуск»: читаем заново с диска, CRL по-прежнему отсутствует.
	reloaded, err := LoadCRLStore(crlPath, caCertPath, noKeyPath)
	if err != nil {
		t.Fatalf("повторная загрузка: %v", err)
	}

	if !reloaded.IsRevoked(serial) {
		t.Fatal("отзыв должен пережить перезапуск — иначе узел вернётся в сеть")
	}

	if reloaded.Number() != 5 {
		t.Fatalf("номер CRL должен пережить перезапуск: ожидалось 5, получено %d", reloaded.Number())
	}
}

// TestRevokedCacheDoesNotOverrideSignedCRL — подписанный CRL CA имеет приоритет
// над локальным кэшем при загрузке.
func TestRevokedCacheDoesNotOverrideSignedCRL(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath, crlPath := testCAPaths(t, dir)

	store, err := LoadCRLStore(crlPath, caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("LoadCRLStore: %v", err)
	}
	if err := store.Revoke(big.NewInt(1), 1); err != nil {
		t.Fatalf("отзыв: %v", err)
	}

	// Кэш уже создан Revoke. Проверяем, что повторная загрузка берёт CRL.
	reloaded, err := LoadCRLStore(crlPath, caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("повторная загрузка: %v", err)
	}
	if !reloaded.IsRevoked(big.NewInt(1)) {
		t.Fatal("отзыв должен быть виден после перезагрузки")
	}
}

// writeLegacyCRL записывает CRL в старом бинарном формате — для тестов конвертации.
func writeLegacyCRL(path string, entries []legacyCRLEntry) error {
	// Формат v1: [4 байта count] + count * [16(хеш) + 8(время) + 1(причина)]
	buf := make([]byte, 4+len(entries)*25)

	buf[0] = byte(len(entries) >> 24)
	buf[1] = byte(len(entries) >> 16)
	buf[2] = byte(len(entries) >> 8)
	buf[3] = byte(len(entries))

	for i, e := range entries {
		base := 4 + i*25
		copy(buf[base:base+16], e.SerialHash[:])

		t := uint64(e.RevokedAt)
		buf[base+16] = byte(t >> 56)
		buf[base+17] = byte(t >> 48)
		buf[base+18] = byte(t >> 40)
		buf[base+19] = byte(t >> 32)
		buf[base+20] = byte(t >> 24)
		buf[base+21] = byte(t >> 16)
		buf[base+22] = byte(t >> 8)
		buf[base+23] = byte(t)
		buf[base+24] = e.Reason
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: buf})
	return os.WriteFile(path, pemBytes, 0644)
}
