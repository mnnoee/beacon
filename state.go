package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// stateFileName — имя файла состояния, который маячок пишет для монитора.
const stateFileName = "state.json"

// BeaconState — состояние маячка, передаваемое монитору.
//
// Только то, что нужно для отображения: имена и адреса пиров. Приватные
// ключи и сертификаты сюда не попадают — файл лежит в общем каталоге
// данных и читается другим процессом.
type BeaconState struct {
	// CN — имя этого узла.
	CN string `json:"cn"`

	// NodeID — его идентификатор в hex.
	NodeID string `json:"node_id"`

	// PeerIPs — CN пира → его адрес.
	//
	// Ключ по имени, а не по NodeID: монитор показывает пользователю имена,
	// и без этого соответствия IP не с чем связать.
	PeerIPs map[string]string `json:"peer_ips"`

	// UpdatedAt — время последнего обновления.
	UpdatedAt string `json:"updated_at"`
}

// StateFilePath возвращает путь к файлу состояния узла.
func (c *Config) StateFilePath() string {
	return c.DataDir + "/" + stateFileName
}

// JSONState собирает состояние узла для монитора.
func (b *BeaconNode) JSONState() *BeaconState {
	b.mu.RLock()
	defer b.mu.RUnlock()

	state := &BeaconState{
		CN:        b.config.NodeName,
		NodeID:    sprintfNodeID(b.nodeID),
		PeerIPs:   make(map[string]string),
		UpdatedAt: nowRFC3339(),
	}

	// Имена берём из сертификатов узла: сертификат связывает NodeID и CN,
	// поэтому по нему имя достоверно. Без него в мониторе были бы nodeID'ы.
	for _, cert := range b.trustStore.getTrustedCerts() {
		if cert == nil || cert.Subject.CommonName == "" {
			continue
		}

		// Собственный узел пиром не является: без этой проверки он попадал бы
		// в state.json при любом соединении с самим собой.
		if cert.Subject.CommonName == b.config.NodeName {
			continue
		}

		for _, peer := range b.peers {
			id, err := NodeIDFromCert(cert)
			if err != nil || id != peer.NodeID {
				continue
			}
			if peer.Addr != nil {
				state.PeerIPs[cert.Subject.CommonName] = peer.Addr.IP.String()
			}
			break
		}
	}

	return state
}

// sprintfNodeID форматирует NodeID в верхнем регистре hex.
func sprintfNodeID(id [16]byte) string {
	return fmt.Sprintf("%X", id)
}

// nowRFC3339 возвращает текущее время в формате RFC3339.
func nowRFC3339() string {
	return time.Now().Format(time.RFC3339)
}

// readBeaconState читает файл состояния монитора.
func readBeaconState(path string) (*BeaconState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	state := &BeaconState{}
	if err := json.Unmarshal(data, state); err != nil {
		return nil, err
	}

	return state, nil
}
