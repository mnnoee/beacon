package main

import (
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// encryptedKeyPEMType — тип PEM-блока с зашифрованным приватным ключом.
//
// Обычный парсер PEM этот блок пропустит: с ним нужно сначала снять
// шифрование. Такой тип выбран с тем же расчётом, что и "ENCRYPTED PRIVATE
// KEY" из openssl, — файл остаётся читаемым как PEM, но не как ключ.
const encryptedKeyPEMType = "ENCRYPTED BEACON KEY"

// passphraseEnvVar — переменная окружения с секретом шифрования ключей.
const passphraseEnvVar = "BEACON_PASSPHRASE"

var (
	passphraseMu sync.RWMutex
	passphrase   string
)

// SetPassphrase задаёт секрет для шифрования ключей на диске.
//
// Пустой секрет означает режим «как раньше»: ключи пишутся и читаются без
// шифрования. Задаётся один раз при разборе CLI, дальше все операции с
// приватными ключами идут через него.
func SetPassphrase(p string) {
	passphraseMu.Lock()
	defer passphraseMu.Unlock()
	passphrase = p
}

// Passphrase возвращает текущий секрет шифрования.
func Passphrase() string {
	passphraseMu.RLock()
	defer passphraseMu.RUnlock()
	return passphrase
}

// resolvePassphrase достаёт секрет из файла или переменной окружения.
//
// Приоритет у файла: он позволяет не держать секрет в окружении процесса,
// которое видно через /proc. Пустой результат — не ошибка, а осознанный
// выбор «ключи без шифрования».
func resolvePassphrase(file string) (string, error) {
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("чтение файла с секретом %s: %w", file, err)
		}

		secret := strings.TrimRight(string(data), "\r\n")
		if strings.TrimSpace(secret) == "" {
			return "", fmt.Errorf("файл с секретом %s пуст", file)
		}

		return secret, nil
	}

	secret := os.Getenv(passphraseEnvVar)
	if strings.TrimSpace(secret) == "" {
		return "", nil
	}

	return secret, nil
}

// encryptPrivateKeyPEM кодирует DER-ключ в PEM, шифруя его при заданном секрете.
//
// Без секрета результат ничем не отличается от прежнего: тот же PEM-блок, те же
// права, тот же парсер. С секретом появляется блок ENCRYPTED BEACON KEY.
func encryptPrivateKeyPEM(pemType string, der []byte) ([]byte, error) {
	secret := Passphrase()
	if secret == "" {
		return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}), nil
	}

	encrypted, err := EncryptKey(der, secret)
	if err != nil {
		return nil, fmt.Errorf("шифрование ключа: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: encryptedKeyPEMType, Bytes: encrypted}), nil
}

// decryptPrivateKeyPEM снимает шифрование с PEM-блока.
//
// Для незашифрованного блока возвращается (der, false, nil) — вызывающий сам
// решает, что делать: прочитать как есть или перешифровать при миграции.
func decryptPrivateKeyPEM(data []byte) ([]byte, bool, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, false, fmt.Errorf("не удалось декодировать PEM-блок приватного ключа")
	}

	if block.Type != encryptedKeyPEMType {
		return block.Bytes, false, nil
	}

	secret := Passphrase()
	if secret == "" {
		return nil, true, fmt.Errorf("ключ зашифрован, но секрет не задан: "+
			"укажите -passphrase-file <файл> или переменную %s", passphraseEnvVar)
	}

	der, err := DecryptKey(block.Bytes, secret)
	if err != nil {
		// Текст ошибки DecryptKey самодостаточен («неверный пароль или повреждены
		// данные») — префикс здесь лишь продублировал бы его.
		return nil, true, err
	}

	return der, true, nil
}

// SavePrivateKeyFile сохраняет приватный ключ, шифруя его при заданном секрете.
//
// Запись атомарная (tmp + rename): оборванный процесс не должен оставить
// после себя ключ, который уже не читается.
func SavePrivateKeyFile(path, pemType string, der []byte) error {
	data, err := encryptPrivateKeyPEM(pemType, der)
	if err != nil {
		return err
	}

	return writeFileAtomic(path, data, 0600)
}

// LoadPrivateKeyFile читает приватный ключ, снимая шифрование при необходимости.
//
// Прозрачная миграция: если секрет задан, а ключ на диске ещё лежит открытым,
// он перешифровывается на месте. Иначе шифрование включалось бы только для
// новых выпусков, а все уже выпущенные ключи оставались бы открытыми —
// ровно то, чего шифрование должно было предотвратить.
func LoadPrivateKeyFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("чтение ключа %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM-блок в %s", path)
	}

	der, encrypted, err := decryptPrivateKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	if !encrypted && Passphrase() != "" {
		if err := migrateKeyToEncrypted(path, block.Type, der); err != nil {
			// Миграция не должна ломать работу: ключ уже в памяти.
			log.Printf("[Keys] ключ %s не перешифрован на месте: %v", path, err)
		}
	}

	return der, nil
}

// migrateKeyToEncrypted перешифровывает открытый ключ на месте.
func migrateKeyToEncrypted(path, pemType string, der []byte) error {
	data, err := encryptPrivateKeyPEM(pemType, der)
	if err != nil {
		return err
	}

	info, err := os.Stat(path)
	mode := os.FileMode(0600)
	if err == nil {
		mode = info.Mode().Perm()
	}

	if err := writeFileAtomic(path, data, mode); err != nil {
		return err
	}

	log.Printf("[Keys] ключ %s перешифрован на диске", path)

	return nil
}

// writeFileAtomic пишет файл через временный и подменяет его rename'ом.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("создание директории %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("создание временного файла в %s: %w", dir, err)
	}
	tmpName := tmp.Name()

	defer os.Remove(tmpName) // после успешного rename файл уже не существует

	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("установка прав на %s: %w", tmpName, err)
	}

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("запись %s: %w", tmpName, err)
	}

	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("сброс %s на диск: %w", tmpName, err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("закрытие %s: %w", tmpName, err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("подмена %s: %w", path, err)
	}

	return nil
}
