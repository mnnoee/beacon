# Network Beacons (Сетевые Маячки)

Распределенная система для автоматического обнаружения устройств в локальной сети и организации защищенной P2P-сети с взаимной аутентификацией.

## Архитектура

```
┌─────────────────────────────────────────────────┐
│              Control Node (CA)                  │
│  ┌──────────────────────────────────────────┐   │
│  │  • Генерация корневого CA (ECDSA P-256) │   │
│  │  • Выдача сертификатов для маячков      │   │
│  │  • Отзыв сертификатов (CRL)             │   │
│  └──────────────────────────────────────────┘   │
└─────────────────────┬───────────────────────────┘
                      │ provisioning (USB/файл)
          ┌───────────┴───────────┐
          ▼                       ▼
┌──────────────────┐    ┌──────────────────┐
│  Beacon Node 1   │◄──►│  Beacon Node 2   │
│  (Роутер/AP)     │    │  (Сервер/NAS)    │
│                  │    │                  │
│ • UDP Discovery  │    │ • UDP Discovery  │
│ • mTLS P2P       │    │ • mTLS P2P       │
│ • Gossip CRL     │    │ • Gossip CRL     │
└──────────────────┘    └──────────────────┘
        ▲                       ▲
        └───────────┬───────────┘
                    ▼
            ┌──────────────┐
            │ Beacon Node N│
            └──────────────┘
```

### Роли

**Control Node (CA)** — центр управления ключами. Может быть 1 или 2 (для отказоустойчивости). Обязательна только для начальной настройки и отзыва сертификатов.

**Beacon Node** — автономный узел сети. После provisioning работает без подключения к CA, обнаруживает пирами через UDP broadcast и устанавливает защищенные P2P-соединения.

### Безопасность

| Угроза | Защита |
|--------|--------|
| UDP Spoofing / Rogue Beacons | Discovery-пакеты подписаны Ed25519. Реальное общение — только после mTLS. |
| Replay Attacks | Nonce (32 байта) + timestamp (±5 минут) в каждом UDP-пакете. |
| MITM | Взаимная аутентификация (Mutual TLS). Обе стороны проверяют сертификат через общий CA. |
| Key Compromise | CRL (список отозванных сертификатов) распространяется через gossip-протокол. |
| Broadcast Storms | Token-bucket rate limiter на UDP-сокете (по умолчанию 2 pkt/s, burst 10). |
| Ключи на диске | Шифрование AES-256-GCM + PBKDF2 (600K итераций). Права файлов 0600. |

## Сборка

```bash
# Локальная сборка (x86_64)
go build -o beacon

# Кросс-компиляция для aarch64 (Android/Termux, Raspberry Pi)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o beacon-arm64

# Кросс-компиляция для aarch64 Linux (серверы)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o beacon-arm64
```

Бинарник один — переключение между ролями через CLI-команды.

## Быстрый старт

### 1. Генерация CA

```bash
beacon ca generate-ca -dir ./beacon-data
```

Создаст:
- `./beacon-data/ca/ca-key.pem` — приватный ключ CA (права 0600)
- `./beacon-data/ca/ca-cert.pem` — сертификат CA (распространяется среди маячков)

**Важно:** сделайте бэкап `ca-key.pem` в безопасное место. При его утрате вы не сможете выдавать новые сертификаты.

### 2. Выдача сертификатов для маячков

```bash
beacon ca provision-beacon -dir ./beacon-data roter
beacon ca provision-beacon -dir ./beacon-data nas
beacon ca provision-beacon -dir ./beacon-data ap-top
```

Для каждого маячка создаются:
- `./beacon-data/beacon-<имя>/cert.pem` — TLS-сертификат (90 дней)
- `./beacon-data/beacon-<имя>/key.pem` — приватный ключ (ECDSA P-256)
- `./beacon-data/beacon-<имя>/ed25519-key.pem` — ключ для UDP-подписей (генерируется при первом запуске)

### 3. Распрранение данных

Скопируйте на каждый узел:
- Бинарник `beacon`
- Директория с данными (или только CA-сертификат + сертификат/ключ данного маячка)

```bash
# Пример для удаленного узла
scp beacon nas:~/beacon
scp -r ./beacon-data/beacon-nas nas:~/beacon-data/
scp ./beacon-data/ca/ca-cert.pem nas:~/beacon-data/ca/
```

### 4. Запуск маячков

```bash
# На каждом узле:
beacon beacon -dir ~/beacon-data -name beacon-<имя>

# С явным указанием параметров сети:
beacon beacon \
  -dir ~/beacon-data \
  -name beacon-roter \
  -bind 0.0.0.0 \
  -broadcast 192.168.1.255 \
  -disc-port 1984 \
  -tls-port 1985
```

### 5. Проверка

```bash
# Просмотр списка доверенных узлов
beacon ca list-trusted -dir ./beacon-data

# Логи работы маячка (после запуска)
tail -f ~/beacon.log
```

## CLI-команды

### Control Node (CA)

```bash
# Генерация корневого CA
beacon ca generate-ca -dir <директория>

# Выдача сертификата новому маячку
beacon ca provision-beacon -dir <директория> <имя-маячка>

# Отзыв сертификата (по SHA-256 хешу distinguished name)
beacon ca revoke-beacon -dir <директория> <hex-serial-32-char>

# Список доверенных узлов и CRL
beacon ca list-trusted -dir <директория>

# Импорт CA-сертификата из внешнего файла
beacon ca import-ca -dir <директория> <путь-к-сертификату>
```

### Beacon Node

```bash
beacon beacon [опции]
```

| Опция | По умолчанию | Описание |
|-------|-------------|----------|
| `-name` | (обязательно) | Имя этого маячка (должно совпадать с выданным через provision) |
| `-dir` | `./beacon-data` | Директория с данными (ключи, сертификаты) |
| `-bind` | `0.0.0.0` | Адрес привязки TCP-слушателя |
| `-broadcast` | `255.255.255.255` | Адрес для UDP broadcast |
| `-disc-port` | `1984` | UDP-порт обнаружения |
| `-tls-port` | `1985` | TCP-порт TLS-соединений |
| `-rate-limit` | `2.0` | Макс. пакетов/сек от одного IP |
| `-rate-burst` | `10` | Макс. burst пакетов |

## Протокол

### Discovery (UDP)

Каждые 5 секунд маячок отправляет broadcast-пакет:

```
┌────────┬─────────┬──────┬────────┬───────────┬───────┬─────────┬──────────┐
│ Magic  │ Version │ Type │ NodeID │ Timestamp │ Nonce │ Payload │ Signature│
│ 4 byte │ 1 byte  │ 1 B  │ 16 B   │ 8 B       │ 32 B  │ var     │ 64 B     │
└────────┴─────────┴──────┴────────┴───────────┴───────┴─────────┴──────────┘
  0x4245434E ("BECN")    Ed25519
```

Типы пакетов:
- `0x01` **Announce** — объявление о присутствии
- `0x02` **Echo** — ответ на Announce
- `0x03` **Gossip** — передача обновлений CRL

### Handshake

```
Beacon A                     Beacon B
    │                            │
    │──── Announce (UDP) ───────►│
    │◄─── Echo (UDP) ───────────│
    │                            │
    │──── TLS ClientHello ──────►│
    │◄─── TLS ServerHello ──────│
    │──── TLS Certificate ──────►│  (клиент представляет сертификат)
    │◄─── TLS Certificate ──────│  (сервер представляет сертификат)
    │                            │
    │  [обе стороны проверяют    │
    │   сертификат через CA]     │
    │                            │
    │◄═══ защищенный канал ═════►│
    │     (gossip, данные)       │
```

### Gossip (CRL)

При установке P2P-соединения и каждые 30 минут маячки обмениваются CRL:
- Каждый пакет содержит `CRLVersion` (монотонный счетчик)
- Принимаем обновления только если версия отправителя новее нашей
- CRL сохраняется на диск немедленно

## Примеры использования

### Домашняя сеть

```bash
# Роутер (192.168.1.1)
beacon beacon -dir ~/beacon-data -name beacon-roter -broadcast 192.168.1.255

# NAS (192.168.1.10)
beacon beacon -dir ~/beacon-data -name beacon-nas -broadcast 192.168.1.255

# Точка доступа (192.168.1.2)
beacon beacon -dir ~/beacon-data -name beacon-ap -broadcast 192.168.1.255
```

### Несколько подсетей

Если устройства в разных подсетях,.broadcast-адрес должен быть уникальным для каждой подсети. Маячки в разных подсетях не обнаружат друг друга автоматически — потребуется ручное добавление через TLS (планируется).

### Отзыв скомпрометированного узла

```bash
# 1. Найти serial hash отозванного сертификата
beacon ca list-trusted -dir ./beacon-data

# 2. Отозвать
beacon ca revoke-beacon -dir ./beacon-data <serial-hash>

# 3. CRL автоматически распространится через gossip при следующем P2P-контакте
```

## Требования

- Go 1.21+ (для сборки)
- Никаких внешних зависимостей (zero-dependency)
- Linux (тестировано на amd64, aarch64)
- Сетевой интерфейс с поддержкой UDP broadcast

## Тестирование

```bash
# Запуск всех тестов
go test -v -count=1 ./...

# Тесты покрывают:
# - Полный PKI workflow (CA → provisioning → mTLS)
# - Отзыв сертификатов (CRL persistence)
# - Gossip CRL merge
# - Wire protocol serialization
# - Rate limiter
# - Шифрование/дешифрование ключей (AES-256-GCM + PBKDF2)
```

## Структура файлов

```
beacon/
├── main.go          # CLI: точки входа для ca и beacon
├── config.go        # Конфигурация, порты, дефолты
├── ca.go            # CA: генерация, выдача, отзыв сертификатов, CRL
├── keys.go          # Крипто: Ed25519/ECDSA ключи, PBKDF2, AES-GCM
├── truststore.go    # Trust Store: проверка сертификатов, CRL, gossip
├── protocol.go      # Wire format: discovery-пакеты, gossip payload
├── ratelimit.go     # Token-bucket rate limiter
├── discovery.go     # UDP broadcast с Ed25519-подписями
├── transport.go     # Mutual TLS (сервер + клиент)
├── beacon.go        # Основная логика: discovery → handshake → P2P
└── beacon_test.go   # Интеграционные тесты
```

## Известные ограничения

1. **Физический доступ к CA** — если украден ключ CA, вся сеть скомпрометирована. Рекомендуется HSM/TPM или шифрование ключа CA паролем.
2. **Синхронизация часов** — timestamp ±5 минут. NTP обязателен.
3. **Нет DNS** — подключение по IP, CN используется как логический идентификатор.
4. **Первичное доверие (TOFU)** — ключи передаются через USB/файл при начальной настройке.
5. **Одна подсеть** — discovery работает только в пределах одного broadcast-домена.
