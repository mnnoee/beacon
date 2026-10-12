package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
)

// DeriveKeyPBKDF2 выводит ключ из пароля методом PBKDF2-HMAC-SHA256.
// Реализация основана на RFC 8018 §5.2, использует только stdlib.
//
// 600 000 итераций (рекомендация OWASP 2023) дают адекватную защиту
// от brute-force даже на GPU.
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
		u1 := mac.Sum(nil)

		// result = U1 (копируем для аккумуляции XOR)
		result := make([]byte, hLen)
		copy(result, u1[:hLen])

		// Для каждой итерации: U_i = HMAC(password, U_{i-1}), result ^= U_i
		prev := u1[:hLen]
		for i := 1; i < iterations; i++ {
			mac.Reset()
			mac.Write(prev)
			uNext := mac.Sum(nil)
			for j := 0; j < hLen; j++ {
				result[j] ^= uNext[j]
			}
			copy(prev, uNext[:hLen])
		}

		start := (block - 1) * hLen
		end := start + hLen
		if end > keyLen {
			end = keyLen
		}
		copy(dk[start:end], result[:end-start])
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

// Типы PEM-блоков приватных ключей.
//
// При заданном секрете вместо них на диск ложится блок ENCRYPTED BEACON KEY,
// поэтому чтение идёт через LoadPrivateKeyFile, а не напрямую через pem.Decode.
const (
	ecPrivateKeyPEMType = "EC PRIVATE KEY"
	privateKeyPEMType   = "PRIVATE KEY"
)

// parseEd25519PrivateKey разбирает DER Ed25519-приватного ключа.
func parseEd25519PrivateKey(der []byte) (ed25519.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("парсинг приватного ключа: %w", err)
	}

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ключ не Ed25519 (тип %T)", key)
	}

	return edKey, nil
}
