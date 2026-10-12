package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// peersDirName — каталог, куда складываются сертификаты, полученные от соседей.
//
// Отдельно от beacon-*/, потому что это разное: beacon-*/ — своя выдача,
// peers/ — то, что нам прислали по mTLS. Смешав их, нельзя было бы отличить
// «свой ключ потерян» от «сосед прислал чужой сертификат».
const peersDirName = "peers"

// PeersDir возвращает путь к каталогу сертификатов соседей.
func PeersDir(dataDir string) string {
	return filepath.Join(dataDir, peersDirName)
}

// PeerCertPath возвращает путь к сертификату соседа с данным CN.
func PeerCertPath(dataDir, cn string) string {
	return filepath.Join(PeersDir(dataDir), cn+".cert.pem")
}

// ShareCertificate отправляет свой сертификат соседу по установленному mTLS.
//
// Нужен потому, что в P2P-сети нет центра, куда можно сходить за списком
// участников. Без обмена каждый узел знает только себя: имя соседа не
// разрешается в адрес, его сертификат не находится в TrustStore (поэтому
// SSH к нему невозможен), а gossip-подпись нечем проверить.
//
// Отправляется НЕ по broadcast, а только по уже установленному TLS-соединению:
// получатель уже проверил наш сертификат, значит в канал попадает не кто попало.
func ShareCertificate(ownCertPath string, conn *tls.Conn, priv ed25519.PrivateKey, nodeID [16]byte) error {
	certData, err := os.ReadFile(ownCertPath)
	if err != nil {
		return fmt.Errorf("чтение своего сертификата: %w", err)
	}

	// Сертификат должен быть записан PEM-блоком: иначе разбор на той стороне
	// придёт к молчаливому отбрасыванию.
	if block, _ := pem.Decode(certData); block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("сертификат %s не является PEM-блоком CERTIFICATE", ownCertPath)
	}

	pkt := &DiscoveryPacket{
		Magic:     DiscoveryMagic,
		Version:   ProtocolVersion,
		Type:      PktCertShare,
		NodeID:    nodeID,
		Timestamp: time.Now().Unix(),
		Payload:   certData,
	}
	if _, err := rand.Read(pkt.Nonce[:]); err != nil {
		return fmt.Errorf("генерация nonce: %w", err)
	}

	if _, err := conn.Write(SignPacket(pkt, priv)); err != nil {
		return fmt.Errorf("отправка сертификата: %w", err)
	}

	return nil
}

// AcceptCertificate принимает сертификат соседа и сохраняет его в peers/.
//
// Четыре проверки, и все обязательны:
//
//  1. payload — валидный сертификат;
//  2. сертификат подписан нашим CA и не отозван (IsTrusted);
//  3. его Ed25519-ключ соответствует NodeID пакета — иначе узел преподносит
//     чужой сертификат под своим именем;
//  4. для этого CN ещё не сохранён сертификат с ДРУГИМ ключом.
//
// Четвёртая проверка — не перестраховка. `provision-beacon` не гарантирует
// уникальности ключей по имени (пере-выдача даёт новый ключ на тот же CN),
// поэтому злоумышленник с валидным сертификатом может штурмовать соседа
// сертификатом с чужим CN. Автоматический выбор «победил первый» означал бы,
// что легитимная пере-выдача и атака неразличимы; поэтому конфликт — это
// всегда ошибка с записью в лог, а не молчаливое перезатирание.
func AcceptCertificate(dataDir string, ts *TrustStore, pkt *DiscoveryPacket) (stored bool, err error) {
	cert, err := ParseCertificatePEM(pkt.Payload)
	if err != nil {
		return false, fmt.Errorf("payload не является сертификатом: %w", err)
	}

	// Проверка 1: сертификат подписан нашим CA и не отозван.
	if ts != nil && !ts.IsTrusted(cert) {
		return false, fmt.Errorf("сертификат CN=%s не подписан нашим CA или отозван", cert.Subject.CommonName)
	}

	// Проверка 2: ключ из сертификата обязан давать NodeID пакета.
	if certID, err := NodeIDFromCert(cert); err == nil {
		if certID != pkt.NodeID {
			return false, fmt.Errorf("ключ сертификата CN=%s даёт nodeID %X, не %X",
				cert.Subject.CommonName, certID, pkt.NodeID)
		}
	}

	// Проверка 3: конфликт CN с другим ключом.
	if existing, err := loadPeerCertAny(ts, cert.Subject.CommonName); err == nil {
		if existing.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			return false, fmt.Errorf("для CN=%s уже есть сертификат %s с другим серийником: "+
				"возможна подмена или пере-выдача — новый сертификат не сохранён",
				cert.Subject.CommonName, existing.SerialNumber)
		}
	}

	path := PeerCertPath(dataDir, cert.Subject.CommonName)

	if err := os.MkdirAll(PeersDir(dataDir), 0700); err != nil {
		return false, fmt.Errorf("создание каталога %s: %w", peersDirName, err)
	}

	if err := os.WriteFile(path, pkt.Payload, 0644); err != nil {
		return false, fmt.Errorf("сохранение сертификата соседа: %w", err)
	}

	// Добавляем в память сразу, а не после перезапуска: иначе следующая
	// проверка конфликта CN не увидела бы этот сертификат.
	ts.AddTrustedCert(cert)

	// Сразу регистрируем ключ подписи: иначе до перезапуска его не будет,
	// и gossip от этого узла не пройдёт проверку.
	if nodeID, err := NodeIDFromCert(cert); err == nil {
		if pub, err := Ed25519PubFromCert(cert); err == nil {
			ts.RegisterEd25519Key(nodeID, pub)
		}
	}

	return true, nil
}

// loadPeerCertAny ищет известный сертификат для CN среди всех хранилищ.
func loadPeerCertAny(ts *TrustStore, cn string) (*x509.Certificate, error) {
	if ts == nil {
		return nil, fmt.Errorf("TrustStore не задан")
	}

	for _, cert := range ts.getTrustedCerts() {
		if cert != nil && cert.Subject.CommonName == cn {
			return cert, nil
		}
	}

	return nil, fmt.Errorf("сертификат для CN=%s не найден", cn)
}

// PeerCertificates читает сертификаты соседей из dataDir/peers/.
//
// Берём только *.pem в этом каталоге: соседние резервные копии и служебные
// файлы иначе ушли бы в TrustStore как доверенные сертификаты.
func PeerCertificates(dataDir string) []*x509.Certificate {
	dir := PeersDir(dataDir)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var certs []*x509.Certificate

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".pem" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}

		cert, err := ParseCertificatePEM(data)
		if err != nil {
			continue
		}

		certs = append(certs, cert)
	}

	return certs
}
