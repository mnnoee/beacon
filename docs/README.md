# Network Beacons (Сетевые Маячки)

Распределенная система обнаружения устройств в LAN с SSH-доступом, защищенной P2P-сетью и TUI-монитором.

## Обзор

Единый Go-бинарник с четырьмя режимами:

| Режим | Команда | Назначение |
|-------|---------|-----------|
| CA | `beacon ca` | Генерация CA, выдача/отзыв сертификатов |
| Beacon | `beacon beacon` | Discovery, mTLS, SSH, gossip |
| SSH | `beacon ssh` | Подключение к другому маячку |
| Monitor | `beacon monitor` | TUI-монитор состояния сети |

## Архитектура

```
┌─────────────────────────────────────────────────────┐
│                  Control Node (CA)                   │
│  • Генерация Root CA (ECDSA P-256)                  │
│  • Выдача сертификатов (provision-beacon)            │
│  • Отзыв сертификатов (CRL)                         │
│  • Экспорт/синхронизация (export-ca, sync-crl)      │
└──────────────────────┬──────────────────────────────┘
                       │ provisioning (USB/файл)
           ┌───────────┴───────────┐
           ▼                       ▼
┌──────────────────┐    ┌──────────────────┐
│  Beacon Node 1   │◄──►│  Beacon Node 2   │
│                  │    │                  │
│ • UDP Discovery  │    │ • UDP Discovery  │
│ • mTLS P2P       │    │ • mTLS P2P       │
│ • SSH Server     │    │ • SSH Server     │
│ • Gossip CRL     │    │ • Gossip CRL     │
│ • TUI Monitor    │    │ • TUI Monitor    │
└──────────────────┘    └──────────────────┘
```

### Стек

| Компонент | Технология |
|-----------|-----------|
| Discovery | UDP broadcast (255.255.255.255), Ed25519-подписи |
| Транспорт | Mutual TLS (ECDSA P-256) |
| SSH | golang.org/x/crypto/ssh |
| TUI | bubbletea + lipgloss + go-runewidth |
| Шифрование ключей | AES-256-GCM + PBKDF2 (600K итераций) |
| Trust Store | CA + CRL + gossip + peers.txt |
| Rate Limiting | Token bucket (per IP) |

### Безопасность

| Угроза | Защита |
|--------|--------|
| UDP Spoofing | Discovery — только «анонс». Реальное общение — после mTLS. |
| Replay Attacks | Nonce (32 Б) + timestamp (±5 мин). |
| MITM | Взаимная аутентификация через общий CA. |
| Key Compromise | CRL через gossip. Отзыв через `revoke-beacon`. |
| Broadcast Storms | Token-bucket rate limiter (2 pkt/s, burst 10). |
| Ключи на диске | AES-256-GCM + PBKDF2. Права 0600. |
| SSH brute-force | Только public key auth, лимит 10 подключений. |
| SSH host key | Проверка через TrustStore (не InsecureIgnoreHostKey). |

### Discovery

UDP broadcast на порт 1984. Multicast (239.19.84.1) поддерживается, но не работает через WiFi-роутеры — по умолчанию broadcast.

```
┌────────┬─────────┬──────┬────────┬───────────┬───────┬─────────┬──────────┐
│ Magic  │ Version │ Type │ NodeID │ Timestamp │ Nonce │ Payload │ Signature│
│ 4 byte │ 1 byte  │ 1 B  │ 16 B   │ 8 B       │ 32 B  │ var     │ 64 B     │
└────────┴─────────┴──────┴────────┴───────────┴───────┴─────────┴──────────┘
```

### Dual CA

Два узла могут работать как CA одновременно:
```bash
# На первой машине
beacon ca generate-ca -dir ./data
beacon ca export-ca -dir ./data

# На второй машине
scp user@first:~/data/ca/* ~/beacon-data/ca/
beacon ca list-trusted -dir ~/beacon-data
```

CRL синхронизируется через `sync-crl` или gossip-протокол.

## Структура файлов

```
beacon/
├── main.go          # CLI: ca / beacon / ssh / monitor
├── config.go        # Конфигурация, порты, дефолты
├── ca.go            # CA, выдача сертификатов, CRL
├── keys.go          # Ed25519/ECDSA, PBKDF2, AES-GCM
├── truststore.go    # Trust Store, CRL, gossip, Ed25519 keys
├── protocol.go      # Wire format discovery-пакетов
├── ratelimit.go     # Token bucket rate limiter
├── discovery.go     # UDP broadcast с fallback multicast
├── transport.go     # Mutual TLS (VerifyPeerCertificate)
├── ssh_server.go    # SSH-сервер (PTY, exec, TrustStore auth)
├── ssh_client.go    # SSH-клиент (host key verification)
├── beacon.go        # Основная логика маячка
├── monitor.go       # TUI (bubbletea + lipgloss)
├── beacon_test.go   # Тесты PKI/mTLS/protocol
├── ssh_test.go      # Тесты SSH
└── docs/
    ├── README.md    # Этот файл
    └── USAGE.md     # Руководство по использованию
```

## Известные ограничения

1. **Физический доступ к CA** — кража ключа = компрометация сети.
2. **Синхронизация часов** — timestamp ±5 минут. NTP обязателен.
3. **Нет DNS** — подключение по IP, CN как логический ID.
4. **TOFU** — ключи передаются через USB/файл при начальной настройке.
5. **Одна подсеть** — discovery в пределах broadcast-домена.
6. **WiFi multicast** — не работает через роутеры, используется broadcast.
