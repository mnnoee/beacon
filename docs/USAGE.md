# Руководство по использованию

Все примеры проверены на реальных узлах. Флаги соответствуют `beacon <команда> -h`.

## Сборка

```bash
# Локальная машина (x86_64)
CGO_ENABLED=0 go build -o beacon

# Raspberry Pi и прочие 64-битные SBC
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o beacon-arm64

# Роутеры (OpenWrt)
CGO_ENABLED=0 GOOS=linux GOARCH=mipsle go build -o beacon-mipsle
```

Требуется Go 1.26 или новее.

## Быстрый старт

### 1. Генерация CA

```bash
beacon ca generate-ca -dir ./data
```

Создаёт:

- `data/ca/ca-key.pem` — приватный ключ CA (0600, шифруется при заданном секрете)
- `data/ca/ca-cert.pem` — сертификат CA

С секретом шифрования:

```bash
echo 'длинный-секрет' > ~/.beacon-secret
beacon ca generate-ca -dir ./data -passphrase-file ~/.beacon-secret
```

### 2. Выдача сертификатов

```bash
# Узел, который будет только участвовать в сети
beacon ca provision-beacon -dir ./data nas

# Узел, который будет раздавать SSH
beacon ca provision-beacon -dir ./data -role server nas

# Потерян ключ: пере-выдача с предупреждением о старом серийнике
beacon ca provision-beacon -dir ./data -reissue nas
```

Для каждого узла создаётся `data/beacon-<имя>/` с `cert.pem`, `key.pem` и
`ed25519-key.pem` (ключ подписей discovery и gossip).

> Имя задаётся без префикса `beacon-`, он добавляется автоматически. Минимум
> три символа.

### 3. Деплой на узел

```bash
scp beacon nas:~/beacon
scp -r ./data/beacon-nas nas:~/beacon-data/
scp ./data/ca/ca-cert.pem nas:~/beacon-data/ca/
```

Ключ CA на узлы не копируется: он остаётся на машине CA.

### 4. Запуск маячка

```bash
beacon beacon -dir ~/beacon-data -name beacon-nas \
  -broadcast 192.168.1.255
```

SSH-сервер **выключен** по умолчанию. Чтобы включить, нужен ещё и allowlist:

```bash
beacon beacon -dir ~/beacon-data -name beacon-nas \
  -broadcast 192.168.1.255 \
  -ssh -ssh-allow beacon-nas,beacon-nas
```

Ограничение exec-команд (при заданном whitelist интерактивный shell
запрещается):

```bash
beacon beacon ... -ssh -ssh-allow beacon-nas \
  -ssh-allow-commands "uptime,status"
```

Отдельная машина под TUI того же узла:

```bash
beacon beacon -dir ~/beacon-data -name beacon-nas -tui
```

### 5. Монитор

```bash
beacon monitor -dir ~/beacon-data -name beacon-nas -tls-port 1985
```

TUI на bubbletea + lipgloss: таблица соседей, статус ONLINE/OFFLINE, пинг
каждые 3 секунды. Управление: `q` — выход, `r` — перепинговать всех.

`-tls-port` нужен, если маячок запущен на нестандартном порту: без него пинг
идёт на 1985 и живые соседи выглядят недоступными.

### 6. SSH к соседу

```bash
# По имени: имя разрешается в адрес через discovery
beacon ssh -dir ~/beacon-data -name beacon-nas beacon-nas "uptime"

# По адресу
beacon ssh -dir ~/beacon-data -name beacon-nas 192.168.1.20:2222 "uptime"

# Интерактивный shell (нужен терминал)
beacon ssh -dir ~/beacon-data -name beacon-nas beacon-nas
```

Если маячки в другой подсети, клиент запускается с их discovery-портом и
broadcast-адресом:

```bash
beacon ssh -dir ~/beacon-data -name beacon-nas \
  -disc-port 1984 -broadcast 192.168.1.255 -p 2222 beacon-nas "uptime"
```

Требования к обеим сторонам:

- узел назначения запущен с `-ssh` и с CN клиента в `-ssh-allow`;
- сертификат клиента имеет роль `server` (роль `peer` SSH-доступа не даёт);
- клиент знает сертификат соседа — он приезжает сам через cert-share, когда
  маячки работают в одной сети.

## CLI-команды

### Control Node (CA)

| Команда | Описание |
|---------|----------|
| `ca generate-ca` | Генерация корневого CA |
| `ca provision-beacon <имя>` | Выдача сертификата маячку (`-role`, `-reissue`) |
| `ca revoke-beacon -node <CN>` | Отзыв по имени узла |
| `ca revoke-beacon -serial <N>` | Отзыв по серийнику (значение из `list-trusted`) |
| `ca list-trusted` | Таблица доверенных узлов: CN, NodeID, статус, серийник |
| `ca import-ca <путь>` | Импорт чужого CA-сертификата |
| `ca export-ca` | Подсказки по раскладке CA и второй CA-машине |
| `ca sync-crl user@host:/path` | Синхронизация CRL по scp (без shell) |

Общие флаги: `-dir`, `-ca-key`, `-ca-cert`, `-passphrase-file`.

### Beacon Node

```bash
beacon beacon [опции]
```

| Опция | Дефолт | Описание |
|-------|--------|----------|
| `-name` | (обязательно) | Имя маячка |
| `-dir` | `./beacon-data` | Директория данных |
| `-bind` | `0.0.0.0` | Адрес TCP-слушателей (TLS, SSH) |
| `-broadcast` | `255.255.255.255` | Broadcast-адрес discovery |
| `-disc-port` | `1984` | UDP-порт обнаружения |
| `-tls-port` | `1985` | TCP-порт mTLS |
| `-ssh-port` | `2222` | TCP-порт SSH-сервера |
| `-ssh` | выкл. | Включить SSH-сервер |
| `-ssh-allow` | (пусто) | CN с правом входа; пусто = отказ всем, кроме себя |
| `-ssh-allow-commands` | (пусто) | Разрешённые exec-команды; пусто = любые |
| `-ssh-shell` | `/bin/sh` | Интерпретатор для сессий |
| `-ssh-max-conns` | `10` | Макс. одновременных подключений |
| `-ssh-idle-timeout` | `10m` | Таймаут простоя |
| `-rate-limit` | `2.0` | Пакетов/с от одного IP |
| `-rate-burst` | `10` | Burst пакетов |
| `-tui` | выкл. | Показать монитор в этом же процессе |
| `-passphrase-file` | (пусто) | Файл с секретом шифрования ключей |

`-bind` не влияет на discovery: broadcast-пакеты доставляются только сокетам,
слушающим все адреса, поэтому маячок всегда слушает `0.0.0.0`.

### SSH-клиент

```bash
beacon ssh [опции] <цель> [команда]
```

| Опция | Описание |
|-------|----------|
| `-name` | Имя этого маячка (обязательно, идёт в CN сертификата) |
| `-dir` | Каталог данных |
| `-disc-port` | UDP-порт discovery (должен совпадать с маячками) |
| `-broadcast` | Broadcast-адрес |
| `-p` | Порт SSH (переопределяет 2222) |
| `-passphrase-file` | Файл с секретом шифрования ключей |

### TUI-монитор

```bash
beacon monitor [опции]
```

| Опция | Описание |
|-------|----------|
| `-name` | Имя маячка |
| `-dir` | Каталог данных |
| `-tls-port` | Порт для проверки доступности соседей |

Монитор читает `state.json`, который маячок пишет раз в секунду: имя соседа
из сертификатов, адрес — из файла состояния.

## Типичные сценарии

### Сеть из трёх узлов

```bash
# CA-машина
beacon ca generate-ca -dir ./data
beacon ca provision-beacon -dir ./data -role server nas
beacon ca provision-beacon -dir ./data -role server nas
beacon ca provision-beacon -dir ./data             ap

# На каждом узле: файлы маячка + сертификат CA, затем запуск
beacon beacon -dir ~/beacon-data -name beacon-nas \
  -broadcast 192.168.1.255 -ssh -ssh-allow beacon-nas
```

Соседи находят друг друга сами: cert-share раздаёт сертификаты по mTLS, раскладывать
их вручную не нужно.

### Отзыв узла

```bash
beacon ca list-trusted -dir ./data
beacon ca revoke-beacon -dir ./data -node beacon-nas
```

Отзыв подписан CA, расходится по gossip и сохраняется у соседей в
`ca/revoked-cache.json` — узел без ключа CA переживает им перезапуск. Отозванный
узел отвергается на mTLS и SSH.

### Потерянный ключ узла

```bash
# Пере-выдача: печатает старый серийник
beacon ca provision-beacon -dir ./data -reissue beacon-nas
# Разложить новые файлы на узел, затем отозвать старый сертификат
beacon ca revoke-beacon -dir ./data -serial <старый-серийник>
```

Прежний сертификат сохраняется в `ca/replaced/<cn>/<serial>.pem` — иначе его
серийник было бы негде искать.

### Вторая CA-машина

```bash
# На второй машине — свой CA
beacon ca generate-ca -dir ./data2

# Маячок импортирует оба сертификата и получает отзывы от обоих
beacon ca import-ca -dir ~/beacon-data ~/data2/ca/ca-cert.pem
beacon ca sync-crl -dir ~/beacon-data admin@192.168.1.4:/home/admin/data/ca/crl.pem
```

Ключ CA на вторую машину не переносится.

## Диагностика

| Симптом | Причина и что делать |
|---------|---------------------|
| `узел 'X' не найден среди доверенных сертификатов` | Нет сертификата соседа: маячки ещё не соединились или в разных подсетях. `ca list-trusted` покажет, что есть |
| `не найден среди доверенных сертификатов (имя введено с ошибкой или узел отозван)` | Проверьте имя и CRL: `ca list-trusted -dir <dir>` |
| `на имя 'X' отвечают несколько адресов` | Клон или подмена узла: один NodeID на двух адресах. Подключение отменено намеренно |
| `маячок найден в TrustStore, но не ответил в сети` | Не совпал `-disc-port` или `-broadcast`, либо узел за другой подсетью |
| `не предназначен для SSH (нужна роль server)` | У клиентского сертификата роль `peer`. Пере-выдайте с `-role server` |
| `CN не разрешён для SSH на этом узле` | Добавьте CN клиента в `-ssh-allow` на узле назначения |
| `ключ зашифрован, но секрет не задан` | Передайте `-passphrase-file` или `BEACON_PASSPHRASE` |
| Монитор показывает `???` | Нет адреса: ещё не пришёл `state.json` либо сосед не отвечает на broadcast |

## Тестирование

```bash
go test -race ./...          # полный прогон с гонками
go test -cover ./...         # покрытие
gofmt -l . && go vet ./...   # стиль и статический анализ
```

Что покрыто: PKI и выдача, CRL и его версии, gossip-отзывы, cert-share,
обмен по mTLS между двумя живыми узлами, `beacon ssh <имя>` от разрешения имени
до выполнения команды, шифрование ключей и миграция, разбор SSH-протокола,
часовые окна и подписи discovery.

CI (`.github/workflows/ci.yml`) гоняет gofmt, vet, тесты с `-race` и собирает
`linux/amd64`, `arm64`, `mipsle`.