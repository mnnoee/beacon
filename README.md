# Network Beacons (Сетевые Маячки)

Распределенная система обнаружения устройств в LAN и организации защищенной P2P-сети с SSH-доступом.

## Быстрый старт

```bash
# Сборка
go build -o beacon

# Генерация CA + выдача сертификатов
beacon ca generate-ca -dir ./data
beacon ca provision-beacon -dir ./data my-node

# Запуск маячка (discovery + mTLS + SSH)
beacon beacon -dir ./data -name beacon-my-node

# SSH-подключение к другому маячку
beacon ssh -name beacon-my-node 192.168.1.10:2222 "uname -a"
```

## Документация

Полная документация: [docs/README.md](docs/README.md)
