# Network Beacons (Сетевые Маячки)

Распределенная система обнаружения устройств в LAN с SSH-доступом и защищенной P2P-сетью.

## Обзор

Единый Go-бинарник, работающий в двух ролях:

- **Control Node (CA)** — генерирует корневой CA, выдаёт и отзывает сертификаты
- **Beacon Node** — автономный узел: UDP discovery → mTLS P2P → SSH-доступ → gossip CRL

## Архитектура

```
┌───────────────────────────────────────────────────┐
│                Control Node (CA)                  │
│  ┌────────────────────────────────────────────┐   │
│  │  • Генерация Root CA (ECDSA P-256)        │   │
│  │  • Выдача сертификатов (provision)        │   │
│  │  • Отзыв сертификатов (CRL)               │   │
│  └────────────────────────────────────────────┘   │
└──────────────────────┬────────────────────────────┘
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
└──────────────────┘    └──────────────────┘
```

### Стек

| Компонент | Технология |
|-----------|-----------|
| Discovery | UDP broadcast, Ed25519-подписи |
| Транспорт | Mutual TLS (ECDSA P-256) |
| SSH | golang.org/x/crypto/ssh |
| Шифрование ключей | AES-256-GCM + PBKDF2 (600K) |
| Trust Store | CA + CRL + gossip |
| Rate Limiting | Token bucket (per IP) |

### Безопасность

| Угроза | Защита |
|--------|--------|
| UDP Spoofing | Discovery — только «анонс». Реальное общение — после mTLS. |
| Replay Attacks | Nonce (32 Б) + timestamp (±5 мин) в каждом UDP-пакете. |
| MITM | Взаимная аутентификация через общий CA. |
| Key Compromise | CRL распространяется через gossip-протокол. |
| Broadcast Storms | Token-bucket rate limiter (2 pkt/s, burst 10). |
| Ключи на диске | AES-256-GCM + PBKDF2. Права файлов 0600. |
| SSH brute-force | Только public key auth, лимит подключений (10). |

### Протокол Discovery

```
┌────────┬─────────┬──────┬────────┬───────────┬───────┬─────────┬──────────┐
│ Magic  │ Version │ Type │ NodeID │ Timestamp │ Nonce │ Payload │ Signature│
│ 4 byte │ 1 byte  │ 1 B  │ 16 B   │ 8 B       │ 32 B  │ var     │ 64 B     │
└────────┴─────────┴──────┴────────┴───────────┴───────┴─────────┴──────────┘
  0x4245434E ("BECN")    Ed25519
```

Типы: `0x01` Announce, `0x02` Echo, `0x03` Gossip (CRL).

### Handshake

```
Beacon A                     Beacon B
    │──── Announce (UDP) ───────►│
    │◄─── Echo (UDP) ───────────│
    │──── TLS ClientHello ──────►│
    │◄─── TLS ServerHello ──────│
    │──── TLS Certificate ──────►│
    │◄─── TLS Certificate ──────│
    │  [проверка через CA]       │
    │◄═══ защищенный канал ═════►│
```

## Структура файлов

```
beacon/
├── main.go          # CLI: ca / beacon / ssh
├── config.go        # Конфигурация, порты, дефолты
├── ca.go            # CA, выдача сертификатов, CRL
├── keys.go          # Ed25519/ECDSA, PBKDF2, AES-GCM
├── truststore.go    # Trust Store, CRL, gossip
├── protocol.go      # Wire format discovery-пакетов
├── ratelimit.go     # Token bucket rate limiter
├── discovery.go     # UDP broadcast
├── transport.go     # Mutual TLS
├── ssh_server.go    # SSH-сервер (PTY, exec, auth)
├── ssh_client.go    # SSH-клиент
├── beacon.go        # Основная логика маячка
├── beacon_test.go   # Тесты PKI/mTLS/protocol
├── ssh_test.go      # Тесты SSH
└── docs/
    ├── README.md    # Этот файл
    └── USAGE.md     # Руководство по использованию
```

## Известные ограничения

1. **Физический доступ к CA** — кража ключа = компрометация сети. Рекомендуется HSM/TPM.
2. **Синхронизация часов** — timestamp ±5 минут. NTP обязателен.
3. **Нет DNS** — подключение по IP, CN как логический ID.
4. **TOFU** — ключи передаются через USB/файл при начальной настройке.
5. **Одна подсеть** — discovery в пределах broadcast-домена.
