# Руководство по использованию

## Сборка

```bash
# x86_64
go build -o beacon

# aarch64 (Android/Termux, Raspberry Pi)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o beacon-arm64

# mipsle (роутеры OpenWrt)
GOOS=linux GOARCH=mipsle CGO_ENABLED=0 GOMIPS=softfloat go build -o beacon-mipsle
```

## Быстрый старт

### 1. Генерация CA

```bash
beacon ca generate-ca -dir ./data
```

Создаст:
- `data/ca/ca-key.pem` — приватный ключ CA (0600)
- `data/ca/ca-cert.pem` — сертификат CA

### 2. Выдача сертификатов

```bash
beacon ca provision-beacon -dir ./data nas
beacon ca provision-beacon -dir ./data tablet
beacon ca provision-beacon -dir ./data router
```

Для каждого: `data/beacon-<имя>/cert.pem` + `key.pem`

### 3. Деплой

```bash
scp beacon nas:~/beacon
scp -r ./data/beacon-nas nas:~/beacon-data/
scp ./data/ca/ca-cert.pem nas:~/beacon-data/ca/
```

### 4. Создание peers.txt

Для автоматического пинга создайте `~/beacon-data/peers.txt`:

```
# Список пиров (имя IP)
beacon-nas 192.168.1.4
beacon-tablet 192.168.1.214
beacon-router 192.168.1.19
```

### 5. Запуск

```bash
# На каждом узле:
beacon beacon -dir ~/beacon-data -name beacon-<имя> \
  -broadcast 255.255.255.255 -ssh-port 2222
```

### 6. Монитор

```bash
beacon monitor -dir ~/beacon-data -name beacon-<имя>
```

TUI на bubbletea+lipgloss: таблица пиров, статус ONLINE/OFFLINE, пинг каждые 3 сек.
Управление: `q` — выход, `r` — ping всех.

### 7. SSH

```bash
# Подключение по IP
beacon ssh -name beacon-my-node 192.168.1.10:2222 "uname -a"

# Интерактивный shell
beacon ssh -name beacon-my-node 192.168.1.10:2222
```

## CLI-команды

### Control Node (CA)

| Команда | Описание |
|---------|----------|
| `ca generate-ca` | Генерация корневого CA |
| `ca provision-beacon <имя>` | Выдача сертификата маячку |
| `ca revoke-beacon <hex>` | Отзыв сертификата |
| `ca list-trusted` | Список доверенных узлов |
| `ca import-ca <путь>` | Импорт CA-сертификата |
| `ca export-ca` | Экспорт CA-файлов для копирования |
| `ca sync-crl <host:path>` | Синхронизация CRL с другой CA |

### Beacon Node

```bash
beacon beacon [опции]
```

| Опция | Дефолт | Описание |
|-------|--------|----------|
| `-name` | (обязательно) | Имя маячка |
| `-dir` | `./beacon-data` | Директория данных |
| `-bind` | `0.0.0.0` | Адрес привязки |
| `-broadcast` | `255.255.255.255` | Broadcast-адрес |
| `-disc-port` | `1984` | UDP-порт discovery |
| `-tls-port` | `1985` | TCP-порт mTLS |
| `-ssh-port` | `2222` | TCP-порт SSH |
| `-ssh-max-conns` | `10` | Макс. SSH-подключений |
| `-ssh-idle-timeout` | `10m` | SSH idle timeout |
| `-rate-limit` | `2.0` | pkt/s от одного IP |
| `-rate-burst` | `10` | Burst пакетов |

### SSH-клиент

```bash
beacon ssh [опции] <цель> [команда]
```

| Опция | Описание |
|-------|----------|
| `-name` | Имя этого маячка (для аутентификации) |
| `-dir` | Директория с ключами |
| `-p` | Порт SSH |

### TUI-монитор

```bash
beacon monitor [опции]
```

| Опция | Описание |
|-------|----------|
| `-name` | Имя этого маячка |
| `-dir` | Директория с данными |

## Примеры

### Домашняя сеть

```bash
# Роутер
beacon beacon -dir ~/data -name beacon-roter -broadcast 192.168.1.255

# NAS
beacon beacon -dir ~/data -name beacon-nas -broadcast 192.168.1.255

# Точка доступа
beacon beacon -dir ~/data -name beacon-ap -broadcast 192.168.1.255
```

### Dual CA

```bash
# На первой машине (уже есть CA)
beacon ca generate-ca -dir ./data
beacon ca export-ca -dir ./data

# На второй машине
scp user@first:~/data/ca/* ~/beacon-data/ca/
beacon ca list-trusted -dir ~/beacon-data
```

### Отзыв узла

```bash
beacon ca list-trusted -dir ./data
beacon ca revoke-beacon -dir ./data <hex-serial>
# CRL автоматически через gossip
```

### Кросс-компиляция

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o beacon-arm64
GOOS=linux GOARCH=mipsle CGO_ENABLED=0 GOMIPS=softfloat go build -o beacon-mipsle
```

## Тестирование

```bash
go test -v -count=1 ./...
```

Покрытие:
- PKI workflow (CA → cert → mTLS)
- Отзыв сертификатов (CRL persistence)
- Gossip CRL merge
- Wire protocol serialization
- Rate limiter
- AES-256-GCM + PBKDF2
- SSH: валидный/отозванный/самоподписанный сертификат
- SSH exec-команды
