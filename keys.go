package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// DeriveKeyPBKDF2 выводит ключ из пароля методом PBKDF2-HMAC-SHA256.
// Реализация основана на RFC 8018 §5.2, использует только stdlib.
//
// 600 000 итераций (рекомендация OWASP 2023) дают адекватную защиту
// от brute-force даже на GPU. Argon2id был бы лучше, но не входит в stdlib.
func DeriveKeyPBKDF2(password, salt []byte, iterations, keyLen int) []byte {
	hLen := sha256.Size
	dk := make([]byte, keyLen)
	blocks := (keyLen + hLen - 1) / hLen

	for block := 1; block <= blocks; block++ {
		saltBlock := make([]byte, len(salt)+4)
		copy(saltBlock, salt)
		saltBlock[len(salt)] = byte(block >> 24)
		saltBlock[len(salt)+1] = byte(block >> 16)
		saltBlock[len(salt)+2] = byte(block >> 8)
		saltBlock[len(salt)+3] = byte(block)

		mac := hmac.New(sha256.New, password)
		mac.Write(saltBlock)
		u := mac.Sum(nil)

		for i := 1; i < iterations; i++ {
			mac.Reset()
			mac.Write(u)
			uNext := mac.Sum(nil)
			for j := range u {
				u[j] ^= uNext[j]
			}
			u = u[:hLen]
			copy(u, uNext[:hLen])
		}

		start := (block - 1) * hLen
		end := start + hLen
		if end > keyLen {
			end = keyLen
		}
		copy(dk[start:end], u[:end-start])
	}

	return dk
}

// EncryptKey шифрует приватный ключ с помощью AES-256-GCM.
// Ключ шифрования выводится из пароля через PBKDF2-HMAC-SHA256 (600K итераций).
//
// Формат зашифрованных данных:
// [16 байт соль] [12 байт IV] [N байт ciphertext] [16 байт GCM tag]
func EncryptKey(keyData []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("генерация соли: %w", err)
	}

	derivedKey := DeriveKeyPBKDF2([]byte(passphrase), salt, 600000, 32)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("создание AES-блока: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("создание GCM: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("генерация nonce: %w", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, keyData, nil)

	result := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)
	return result, nil
}

// DecryptKey расшифровывает приватный ключ, зашифрованный функцией EncryptKey.
func DecryptKey(encryptedData []byte, passphrase string) ([]byte, error) {
	if len(encryptedData) < 16+12+1 {
		return nil, fmt.Errorf("зашифрованные данные слишком коротки")
	}

	salt := encryptedData[:16]
	nonce := encryptedData[16:28]
	ciphertext := encryptedData[28:]

	derivedKey := DeriveKeyPBKDF2([]byte(passphrase), salt, 600000, 32)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("создание AES-блока: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("создание GCM: %w", err)
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("расшифровка ключа: неверный пароль или повреждены данные")
	}

	return plaintext, nil
}

// SerializePublicKeyPEM кодирует публичный ключ в PEM-формат.
func SerializePublicKeyPEM(pub ed25519.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
}

// SerializePrivateKeyPEM кодирует приватный ключ в PEM-формат.
func SerializePrivateKeyPEM(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("сериализация приватного ключа: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

// DeserializePrivateKeyPEM раскодирует приватный ключ из PEM.
func DeserializePrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM-блок приватного ключа")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("парсинг приватного ключа: %w", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ключ не является Ed25519 (тип %T)", key)
	}
	return edKey, nil
}

// DeserializePublicKeyPEM раскодирует публичный ключ из PEM.
func DeserializePublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM-блок публичного ключа")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("парсинг публичного ключа: %w", err)
	}
	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ключ не является Ed25519 (тип %T)", key)
	}
	return ed25519.PublicKey(edKey), nil
}

// SaveKeyToFile сохраняет PEM-кодированный ключ на диск с ограничением прав доступа.
func SaveKeyToFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("создание директории %s: %w", dir, err)
	}
	return os.WriteFile(path, data, 0600)
}

// ReadFileContents читает весь файл. Если файл не существует, возвращает nil без ошибки.
func ReadFileContents(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return data, nil
}

// GenerateNodeID генерирует случайный 16-байтовый идентификатор узла.
func GenerateNodeID() [16]byte {
	var id [16]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		panic("не удалось сгенерировать random ID: " + err.Error())
	}
	return id
}
