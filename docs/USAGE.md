# Руководство по использованию

## Сборка

```bash
# x86_64
go build -o beacon

# aarch64 (Android/Termux, Raspberry Pi)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o beacon-arm64

# aarch64 Linux
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o beacon-arm64
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
beacon ca provision-beacon -dir ./data roter
beacon ca provision-beacon -dir ./data nas
beacon ca provision-beacon -dir ./data ap-top
```

Для каждого: `data/beacon-<имя>/cert.pem` + `key.pem`

### 3. Деплой

```bash
scp beacon nas:~/beacon
scp -r ./data/beacon-nas nas:~/beacon-data/
scp ./data/ca/ca-cert.pem nas:~/beacon-data/ca/
```

### 4. Запуск

```bash
# На каждом узле:
beacon beacon -dir ~/beacon-data -name beacon-<имя> \
  -broadcast 192.168.1.255 -ssh-port 2222
```

### 5. SSH

```bash
# Подключение по IP
beacon ssh -name beacon-my-node 192.168.1.10:2222

# Выполнение команды
beacon ssh -name beacon-my-node 192.168.1.10:2222 "uname -a"

# Интерактивный shell
beacon ssh -name beacon-my-node 192.168.1.10:2222
```

## CLI-команды

### Control Node (CA)

```bash
beacon ca generate-ca -dir <дир>
beacon ca provision-beacon -dir <дир> <имя>
beacon ca revoke-beacon -dir <дир> <hex-serial>
beacon ca list-trusted -dir <дир>
beacon ca import-ca -dir <дир> <путь>
```

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
| `-p` | Порт SSH (переопределяет авто) |

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

### Отзыв узла

```bash
# Найти serial hash
beacon ca list-trusted -dir ./data

# Отозвать
beacon ca revoke-beacon -dir ./data <serial-hash>

# CRL распространится через gossip автоматически
```

### Кросс-компиляция для aarch64

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o beacon-arm64
scp beacon-arm64 target-host:~/beacon
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
- AES-256-GCM + PBKDF2 шифрование
- SSH: валидный/отозванный/самоподписанный сертификат
- SSH exec-команды
