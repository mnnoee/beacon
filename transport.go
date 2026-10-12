package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
)

// LoadNodeCertificate загружает сертификат узла вместе с приватным ключом.
//
// Отдельная загрузка вместо tls.LoadX509KeyPair: ключ может лежать в блоке
// ENCRYPTED BEACON KEY, а стандартный загрузчик такой блок не понимает и
// отвергает файл целиком. Здесь ключ сначала расшифровывается, а сертификат
// разбирается обычным способом.
func LoadNodeCertificate(certPath, keyPath string) (tls.Certificate, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("чтение сертификата узла: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return tls.Certificate{}, fmt.Errorf("не удалось декодировать сертификат узла %s", certPath)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("парсинг сертификата узла: %w", err)
	}

	key, err := LoadECDSAKey(keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("загрузка приватного ключа узла: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certBlock.Bytes},
		PrivateKey:  key,
		Leaf:        cert,
	}, nil
}

// TLSConfigForNode создаёт tls.Config для TLS-соединений.
//
// Использует взаимную аутентификацию (Mutual TLS):
// - Клиент проверяет сертификат сервера через RootCAs (наш CA)
// - Сертификат клиента проверяется сервером через ClientCAs (наш CA)
// - Обе стороны используют сертификаты, подписанные общим CA
func TLSConfigForNode(certPath, keyPath, caCertPath string) (*tls.Config, error) {
	cert, err := LoadNodeCertificate(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("чтение CA-сертификата: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("не удалось добавить CA-сертификат в пул")
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		RootCAs:      caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	return config, nil
}

// TLSClientConfig создаёт tls.Config для клиента.
// Вместо InsecureSkipVerify использует VerifyPeerCertificate,
// который проверяет сертификат пира через TrustStore (CA + CRL).
func TLSClientConfig(certPath, keyPath, caCertPath string, ts *TrustStore) (*tls.Config, error) {
	config, err := TLSConfigForNode(certPath, keyPath, caCertPath)
	if err != nil {
		return nil, err
	}

	// В P2P-сети нет DNS — подключаемся по IP.
	// Стандартная hostname-проверка не нужна, но цепочка доверия обязательна.
	config.InsecureSkipVerify = true

	// VerifyPeerCertificate заменяет hostname-проверку на проверку через TrustStore:
	// 1. Сертификат пира подписан нашим CA
	// 2. Сертификат не отозван (CRL)
	// 3. CN используется как логический идентификатор
	config.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("пир не предоставил сертификат")
		}
		peerCert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("парсинг сертификата пира: %w", err)
		}
		if ts != nil {
			if !ts.IsTrusted(peerCert) {
				return fmt.Errorf("сертификат пира не доверен (CN=%s)", peerCert.Subject.CommonName)
			}
		} else {
			// Fallback: проверка через RootCAs без CRL
			opts := x509.VerifyOptions{
				Roots:     config.RootCAs,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			}
			if _, err := peerCert.Verify(opts); err != nil {
				return fmt.Errorf("верификация сертификата пира: %w", err)
			}
		}
		log.Printf("[TLS] пир верифицирован: CN=%s", peerCert.Subject.CommonName)
		return nil
	}

	return config, nil
}

// TLSServerListener создаёт TLS-слушатель для принимаемых соединений.
func TLSServerListener(addr string, config *tls.Config) (net.Listener, error) {
	ln, err := tls.Listen("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("запуск TLS-слушателя на %s: %w", addr, err)
	}
	log.Printf("[TLS] слушатель запущен на %s", addr)
	return ln, nil
}

// TLSClientDial устанавливает TLS-соединение с пиром.
func TLSClientDial(addr string, config *tls.Config) (*tls.Conn, error) {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: DefaultDialTimeout},
		"tcp",
		addr,
		config,
	)
	if err != nil {
		return nil, fmt.Errorf("TLS-подключение к %s: %w", addr, err)
	}
	return conn, nil
}

// LoadECDSAKey загружает ECDSA приватный ключ из PEM (в том числе зашифрованный).
func LoadECDSAKey(path string) (*ecdsa.PrivateKey, error) {
	der, err := LoadPrivateKeyFile(path)
	if err != nil {
		return nil, err
	}

	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("парсинг ключа: %w", err)
	}
	return key, nil
}

// LoadECDSACert загружает сертификат из PEM.
func LoadECDSACert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// GenerateToken генератор криптографически стойкого токена.
func GenerateToken(length int) ([]byte, error) {
	token := make([]byte, length)
	if _, err := rand.Read(token); err != nil {
		return nil, fmt.Errorf("генерация токена: %w", err)
	}
	return token, nil
}
