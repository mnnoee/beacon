package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"crypto/x509"
)

// ed25519URIPrefix — префикс SAN URI, в который пишется публичный ключ Ed25519.
//
// Ключ должен быть внутри сертификата, а не только рядом на диске: иначе
// discovery-подпись нечем проверить. Формат:
//
//	urn:beacon:ed25519:<base64url(публичный_ключ_32_байта)>
//
// Основание: RFC 8555 раздел 4.2.1.3 (SAN otherName/URI) — идентичность узла
// привязана к сертификату, а не к файлу на диске, который можно подменить.
const ed25519URIPrefix = "urn:beacon:ed25519:"

// ed25519KeySize — размер публичного ключа Ed25519 в байтах.
const ed25519KeySize = 32

// NodeIDFromEd25519Pub вычисляет идентификатор узла из публичного ключа Ed25519.
//
//	nodeID = SHA-256(ed25519_pubkey)[:16]
//
// Почему именно так, а не первые 16 байт ключа (как было раньше):
//   - идентификатор становится детерминированно выводимым из сертификата,
//     поэтому пира можно опознать сразу после mTLS-рукопожатия, без
//     обращения к диску и без TOFU-записи;
//   - 16 байт от детерминированного хеша не раскрывают ничего сверх публичного
//     ключа, который и так передаётся открыто в сертификате;
//   - SHA-256 равномерно распределяет биты, тогда как у Ed25519-ключа
//     младшие байты несут больше структуры.
func NodeIDFromEd25519Pub(pub ed25519.PublicKey) [16]byte {
	var id [16]byte
	if len(pub) != ed25519KeySize {
		// Некорректный ключ — возвращаем нули, вызывающий код обязан
		// проверить длину через ValidateEd25519Pub до этого вызова.
		return id
	}
	h := sha256.Sum256(pub)
	copy(id[:], h[:16])
	return id
}

// ValidateEd25519Pub проверяет, что публичный ключ имеет корректную длину.
func ValidateEd25519Pub(pub ed25519.PublicKey) error {
	if len(pub) != ed25519KeySize {
		return fmt.Errorf("неверная длина публичного ключа Ed25519: %d байт (ожидается %d)", len(pub), ed25519KeySize)
	}
	return nil
}

// EncodeEd25519URI кодирует публичный ключ в SAN URI.
func EncodeEd25519URI(pub ed25519.PublicKey) (string, error) {
	if err := ValidateEd25519Pub(pub); err != nil {
		return "", err
	}
	return ed25519URIPrefix + base64.RawURLEncoding.EncodeToString(pub), nil
}

// DecodeEd25519URI разбирает SAN URI и извлекает публичный ключ Ed25519.
func DecodeEd25519URI(uri string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(uri, ed25519URIPrefix) {
		return nil, fmt.Errorf("URI не содержит ключ Ed25519: %s", uri)
	}

	encoded := strings.TrimPrefix(uri, ed25519URIPrefix)
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("невалидный base64url в URI Ed25519: %w", err)
	}
	if len(raw) != ed25519KeySize {
		return nil, fmt.Errorf("неверная длина ключа в URI: %d байт (ожидается %d)", len(raw), ed25519KeySize)
	}

	return ed25519.PublicKey(raw), nil
}

// Ed25519URIValue формирует url.URL с ключом для записи в сертификат.
func Ed25519URIValue(pub ed25519.PublicKey) (*url.URL, error) {
	uri, err := EncodeEd25519URI(pub)
	if err != nil {
		return nil, err
	}
	return url.Parse(uri)
}

// Ed25519PubFromCert извлекает публичный ключ Ed25519 из сертификата.
//
// Возвращает ошибку, если в SAN нет ни одного подходящего URI. Это ожидаемая
// ситуация для сертификатов, выпущенных до версии протокола 2: такой узел
// нельзя аутентифицировать по discovery-подписи, поэтому вызывающий код
// обязан сообщить пользователю о необходимости пере-выпустить сертификат.
func Ed25519PubFromCert(cert *x509.Certificate) (ed25519.PublicKey, error) {
	if cert == nil {
		return nil, fmt.Errorf("сертификат не задан")
	}

	for _, u := range cert.URIs {
		if u == nil || !strings.HasPrefix(u.String(), ed25519URIPrefix) {
			continue
		}
		return DecodeEd25519URI(u.String())
	}

	return nil, fmt.Errorf("сертификат CN=%s не содержит публичный ключ Ed25519 в SAN "+
		"(ожидается URI %s<base64url>) — сертификат выпущен до протокола v%d, "+
		"пере-выпустите его командой 'beacon ca provision-beacon -reissue %s'",
		cert.Subject.CommonName, ed25519URIPrefix, ProtocolVersion, cert.Subject.CommonName)
}

// NodeIDFromCert вычисляет идентификатор узла по его сертификату.
func NodeIDFromCert(cert *x509.Certificate) ([16]byte, error) {
	pub, err := Ed25519PubFromCert(cert)
	if err != nil {
		return [16]byte{}, err
	}
	return NodeIDFromEd25519Pub(pub), nil
}
