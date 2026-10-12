package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withPassphrase включает секрет шифрования на время теста.
func withPassphrase(t *testing.T, secret string) {
	t.Helper()

	previous := Passphrase()
	SetPassphrase(secret)
	t.Cleanup(func() { SetPassphrase(previous) })
}

// TestKeysEncryptedOnDiskWhenPassphraseSet — с секретом приватные ключи на
// диске нечитаемы обычным парсером PEM: блок ENCRYPTED BEACON KEY, внутри
// соль, nonce и шифротекст.
func TestKeysEncryptedOnDiskWhenPassphraseSet(t *testing.T) {
	withPassphrase(t, "очень-длинный-секрет-для-теста")

	dir := t.TempDir()

	_, caCertPEM, err := GenerateCA(dir, DefaultCALifetime)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	caKey, err := LoadCAKey(filepath.Join(dir, "ca", "ca-key.pem"))
	if err != nil {
		t.Fatalf("LoadCAKey: %v", err)
	}

	if _, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-узел", time.Hour, RolePeer); err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	for _, name := range []string{"ca/ca-key.pem", "beacon-узел/key.pem", "beacon-узел/" + ed25519KeyFile} {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("чтение %s: %v", name, err)
		}

		if !strings.Contains(string(data), "BEGIN "+encryptedKeyPEMType) {
			t.Fatalf("%s должен быть зашифрован:\n%s", name, data)
		}

		// Права остаются 0600: шифрование не заменяет права доступа.
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Fatalf("права на %s: %o, ожидалось 600", name, perm)
		}
	}

	// Ключ CA при этом читается и подписывает сертификат.
	node, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-другой", time.Hour, RolePeer)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	if node.NodeID == ([16]byte{}) {
		t.Fatal("узел должен получить NodeID")
	}
}

// TestEncryptedKeyNeedsPassphrase — без секрета зашифрованный ключ не читается,
// и ошибка объясняет, что делать.
func TestEncryptedKeyNeedsPassphrase(t *testing.T) {
	dir := t.TempDir()

	withPassphrase(t, "секрет-для-первого-выпуска")
	if _, _, err := GenerateCA(dir, DefaultCALifetime); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	// Читатель без секрета.
	SetPassphrase("")

	_, err := LoadCAKey(filepath.Join(dir, "ca", "ca-key.pem"))
	if err == nil {
		t.Fatal("чтение зашифрованного ключа без секрета должно падать")
	}
	if !strings.Contains(err.Error(), passphraseEnvVar) {
		t.Fatalf("ошибка должна подсказывать, где задать секрет: %v", err)
	}

	// Неверный секрет — тоже ошибка, ключ не подменяется.
	SetPassphrase("неверный")
	if _, err := LoadCAKey(filepath.Join(dir, "ca", "ca-key.pem")); err == nil {
		t.Fatal("неверный секрет должен приводить к ошибке")
	}
}

// TestPlaintextKeyMigratesToEncrypted — ключ, выпущенный до включения
// шифрования, перешифровывается при первом чтении с секретом.
func TestPlaintextKeyMigratesToEncrypted(t *testing.T) {
	dir := t.TempDir()

	// Сначала выпускаем ключи без секрета — как в прежних версиях.
	if _, _, err := GenerateCA(dir, DefaultCALifetime); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	caKeyPath := filepath.Join(dir, "ca", "ca-key.pem")
	before, err := os.ReadFile(caKeyPath)
	if err != nil {
		t.Fatalf("чтение ключа: %v", err)
	}
	if strings.Contains(string(before), encryptedKeyPEMType) {
		t.Fatal("без секрета ключ не должен шифроваться")
	}

	// Теперь включаем секрет и читаем ключ — он должен перешифроваться сам.
	withPassphrase(t, "секрет-после-выпуска")

	if _, err := LoadCAKey(caKeyPath); err != nil {
		t.Fatalf("LoadCAKey: %v", err)
	}

	after, err := os.ReadFile(caKeyPath)
	if err != nil {
		t.Fatalf("повторное чтение ключа: %v", err)
	}
	if !strings.Contains(string(after), encryptedKeyPEMType) {
		t.Fatalf("ключ должен быть перешифрован на месте:\n%s", after)
	}

	// И ключ остаётся рабочим: подпись тем же секретом проверяется.
	withPassphrase(t, "секрет-после-выпуска")
	if _, err := LoadCAKey(caKeyPath); err != nil {
		t.Fatalf("перешифрованный ключ должен читаться: %v", err)
	}
}

// TestResolvePassphrase — приоритет источников и отказ на пустом файле.
func TestResolvePassphrase(t *testing.T) {
	dir := t.TempDir()

	file := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(file, []byte("секрет-из-файла\n"), 0600); err != nil {
		t.Fatalf("запись файла: %v", err)
	}

	// Перевод строки в конце обрезается: иначе секрет не совпал бы с тем,
	// которым ключ шифровался.
	secret, err := resolvePassphrase(file)
	if err != nil {
		t.Fatalf("resolvePassphrase: %v", err)
	}
	if secret != "секрет-из-файла" {
		t.Fatalf("секрет из файла: %q", secret)
	}

	// Файл важнее окружения.
	t.Setenv(passphraseEnvVar, "секрет-из-окружения")
	secret, err = resolvePassphrase(file)
	if err != nil {
		t.Fatalf("resolvePassphrase: %v", err)
	}
	if secret != "секрет-из-файла" {
		t.Fatalf("файл должен побеждать окружение, получено %q", secret)
	}

	// Без файла берётся окружение.
	secret, err = resolvePassphrase("")
	if err != nil {
		t.Fatalf("resolvePassphrase: %v", err)
	}
	if secret != "секрет-из-окружения" {
		t.Fatalf("секрет из окружения: %q", secret)
	}

	// Отсутствие секрета — не ошибка: ключи просто остаются открытыми.
	t.Setenv(passphraseEnvVar, "   ")
	secret, err = resolvePassphrase("")
	if err != nil || secret != "" {
		t.Fatalf("пустое окружение должно давать пустой секрет: %q, %v", secret, err)
	}

	// Пустой файл — ошибка: иначе ключ «зашифруется» пустым секретом.
	empty := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(empty, []byte("\n"), 0600); err != nil {
		t.Fatalf("запись пустого файла: %v", err)
	}
	if _, err := resolvePassphrase(empty); err == nil {
		t.Fatal("пустой файл с секретом должен отвергаться")
	}

	// Отсутствующий файл — тоже ошибка, а не «секрета нет».
	if _, err := resolvePassphrase(filepath.Join(dir, "нет-такого")); err == nil {
		t.Fatal("отсутствующий файл с секретом должен отвергаться")
	}
}

// TestBeaconStartsWithEncryptedKeys — маячок поднимается с зашифрованными
// ключами: TLS, discovery-подпись и SSH host-ключ должны работать.
func TestBeaconStartsWithEncryptedKeys(t *testing.T) {
	withPassphrase(t, "секрет-маячка")

	dir := t.TempDir()
	caCertPEM := newTestCA(t, dir)
	caKey, err := LoadCAKey(filepath.Join(dir, "ca", "ca-key.pem"))
	if err != nil {
		t.Fatalf("LoadCAKey: %v", err)
	}

	if _, err := IssueCertificate(caKey, caCertPEM, dir, "beacon-enc", time.Hour, RoleServer); err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	cfg := DefaultConfig()
	cfg.DataDir = dir
	cfg.NodeName = "beacon-enc"
	cfg.BindAddr = "127.0.0.1"
	cfg.BroadcastAddr = "127.255.255.255"
	cfg.DiscoveryPort = freeUDPPort(t)
	cfg.TLSPort = freeTCPPort(t)
	cfg.SSHPort = 0
	cfg.SSHEnabled = true

	node, err := NewBeaconNode(cfg)
	if err != nil {
		t.Fatalf("NewBeaconNode: %v", err)
	}
	if err := node.Start(); err != nil {
		t.Fatalf("запуск маячка: %v", err)
	}
	t.Cleanup(node.Stop)

	if node.sshServer == nil {
		t.Fatal("SSH-сервер не поднялся с зашифрованным host-ключом")
	}

	// Ключ подписи discovery тоже зашифрован и при этом рабочий.
	edKey, err := loadEd25519Key(cfg.Ed25519KeyPath())
	if err != nil {
		t.Fatalf("Ed25519-ключ маячка: %v", err)
	}
	if got := NodeIDFromEd25519Pub(edKey.Public().(ed25519.PublicKey)); got != node.nodeID {
		t.Fatalf("NodeID %X не совпадает с вычисленным из ключа %X", node.nodeID, got)
	}
}

// TestSSHConnectWithEncryptedClientKeys — клиент с зашифрованными ключами
// подключается к соседу по имени.
func TestSSHConnectWithEncryptedClientKeys(t *testing.T) {
	withPassphrase(t, "секрет-клиента")

	f := newSSHFixture(t)
	serverCfg := f.startServer(t)

	out, err := captureStdout(t, func() error {
		return f.client(t, serverCfg).Connect("beacon-nas", "echo encrypted-ok")
	})
	if err != nil {
		t.Fatalf("подключение по имени: %v", err)
	}
	if !strings.Contains(out, "encrypted-ok") {
		t.Fatalf("команда не отработала, вывод: %q", out)
	}
}
