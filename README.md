# pktdiag (MVP)

Диагностика сети через захват и анализ пакетов. Реализация первой очереди
по ТЗ `pktdiag.md`: CLI без GUI, tshark как анализ-бэкенд, без сторонних
Go-зависимостей (стандартная библиотека + системные `tcpdump`/`tshark`/`capinfos`/`tar`+`zstd`).

## Требования

- Go 1.22+
- `tcpdump`, `tshark`, `capinfos` (пакет `tshark`/`wireshark-common`), `zstd`, `tar` с поддержкой `--zstd`
- root или `CAP_NET_RAW`/`CAP_NET_ADMIN` для захвата трафика

Установка на Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y tcpdump tshark zstd
```

## Сборка

```bash
go build -o pktdiag .
```

## Команды

```bash
pktdiag doctor
# Проверка окружения: наличие tcpdump/tshark/capinfos/zstd, права, диск, интерфейсы

pktdiag capture --iface eth0 --filter "tcp port 443" --duration 30s
# Полный пайплайн: захват -> metadata.json -> report.json/html/md -> архив .tar.zst
# Флаги: --output DIR --format html,json,md --no-archive --ring N --ring-size MB
#        --snaplen N --force (продолжить, даже если doctor нашёл ✘)
# --duration 0 — захват идёт до Ctrl+C

pktdiag report ./pktdiag-capture-.../capture.pcapng --format html,json,md --output ./out
pktdiag report ./bundle.tar.zst
pktdiag report ./captures-dir/
# Строит отчёт по уже существующему pcap/каталогу/бандлу

pktdiag analyze ./bundle.tar.zst --explain
# Печатает человекочитаемую сводку (замена TUI/GUI на этом этапе) и,
# при --explain, подробное объяснение по каждой найденной аномалии.
# --save html,json,md --output DIR — дополнительно сохранить файлы отчёта

pktdiag explain retransmission
pktdiag explain dns_slow
# Explain Engine: норма/warning/critical, причины, рекомендации.
# Список всех терминов — `pktdiag explain` без аргументов.
```

## Что уже есть

- Захват через `tcpdump` (интерфейс, BPF-фильтр, длительность, snaplen,
  базовая поддержка ring buffer через `-C/-W`)
- Сбор метаданных хоста без внешних зависимостей: uname, kernel, CPU, RAM,
  интерфейсы (`/proc/net/dev`, `/sys/class/net`), DNS (`/etc/resolv.conf`),
  таблица маршрутизации (`/proc/net/route`, сырые строки)
- Анализ через `tshark`/`capinfos`: протоколы (TCP/UDP/ICMP/DNS/TLS/HTTP),
  TCP-метрики (retransmission/duplicate ACK/out-of-order/zero window/RST),
  DNS-метрики (запросы/ответы/среднее время/медленные/вероятные таймауты)
- Детектор аномалий с порогами (good/warning/critical) и эвристический
  Health Score (network/tcp/dns)
- Отчёты в JSON/HTML/Markdown + текстовая сводка для терминала
- Архивация результата в `capture-<дата>.tar.zst`
- Explain Engine — база знаний в `internal/explainx/data/explain.json`,
  легко расширяется новыми терминами

## Чего пока нет (следующая итерация)

- TUI (Bubble Tea) — сейчас вместо интерактивных вкладок Overview/TCP/DNS/...
  используется текстовая сводка (`analyze`) и HTML-отчёт
- `pktdiag inspect` / `compare` / `timeline` / `diagnose` / `health` /
  `export` как отдельные команды из UC-13…UC-20 (частично покрыто через
  `report`/`analyze`, но не как отдельные сценарии)
- Анализ нескольких файлов ring-буфера как единого целого (сейчас ring
  buffer только пробрасывается в tcpdump, отчёт строится по одному файлу)
- YAML-конфиг (`pktdiag.yaml`) — сейчас только флаги командной строки
- `iptables`/`nft`/`conntrack`/`sysctl` в metadata (сейчас только
  uname/cpu/ram/интерфейсы/dns/routes)
- Кроссплатформенность — часть sysinfo (`/proc`, `/sys`) linux-specific

## Структура проекта

```
cmd/            обработчики CLI-команд (без cobra — вручную, т.к. сеть
                 в среде сборки блокирует транзитивную зависимость cobra)
internal/
  sysinfo/      сбор метаданных хоста
  capture/      обёртка над tcpdump
  analyze/      обёртка над tshark/capinfos + детектор аномалий + health score
  report/       модель отчёта + рендер в JSON/HTML/MD
  archive/      упаковка в tar.zst
  doctorx/      проверки окружения
  explainx/     Explain Engine (база знаний в data/explain.json)
```
