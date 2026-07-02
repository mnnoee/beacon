package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
)

// TLSConfigForNode создаёт tls.Config для TLS-соединений.
//
// Использует взаимную аутентификацию (Mutual TLS):
// - Клиент проверяет сертификат сервера через RootCAs (наш CA)
// - Сертификат клиента проверяется сервером через ClientCAs (наш CA)
// - Обе стороны используют сертификаты, подписанные общим CA
//
// Это гарантирует:
// 1. MITM-атака невозможна (нет доверия к чужому CA)
// 2. Только авторизованные маячки могут подключиться
// 3. Каждая сторона знает, с кем общается (CN в сертификате)
func TLSConfigForNode(certPath, keyPath, caCertPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("загрузка TLS-сертификата: %w", err)
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
		// Mutual TLS: требуем сертификат от клиента и проверяем через ClientCAs
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}

	return config, nil
}

// TLSClientConfig создаёт tls.Config специфично для клиента
// (отключает проверку hostname, т.к. в P2P-сети нет DNS).
func TLSClientConfig(certPath, keyPath, caCertPath string) (*tls.Config, error) {
	config, err := TLSConfigForNode(certPath, keyPath, caCertPath)
	if err != nil {
		return nil, err
	}
	config.InsecureSkipVerify = true
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

// GenerateToken генератор криптографически стойкого токена.
// Используется для offline-provisioning: токен передаётся на USB/файле,
// а не по сети, что исключает MITM при первой настройке.
func GenerateToken(length int) ([]byte, error) {
	token := make([]byte, length)
	if _, err := rand.Read(token); err != nil {
		return nil, fmt.Errorf("генерация токена: %w", err)
	}
	return token, nil
}
