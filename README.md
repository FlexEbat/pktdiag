# pktdiag (MVP)

Диагностика сети через захват и анализ пакетов. Реализация первой очереди
по ТЗ `pktdiag.md`: CLI без GUI, tshark как анализ-бэкенд, без сторонних
Go-зависимостей (стандартная библиотека + системные `tcpdump`/`tshark`/`capinfos`/`tar`+`zstd`).

## Требования

- Go 1.22+
- `tcpdump`, `tshark`, `capinfos` (пакет `tshark`/`wireshark-common`), `zstd`, `tar` с поддержкой `--zstd`
- root или `CAP_NET_RAW`/`CAP_NET_ADMIN` для захвата трафика
- опционально: `wkhtmltopdf` (для `--format pdf`), `iptables`/`nftables`/`conntrack` (для соответствующих секций metadata.json — без них просто будут пропущены), `mergecap` (входит в `tshark`/`wireshark-common`, нужен для анализа ring buffer)

Установка на Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y tcpdump tshark zstd wkhtmltopdf iptables nftables conntrack
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

pktdiag diagnose ./bundle.tar.zst
# UC-19: группирует найденные аномалии по категориям (потери/задержка/буфер/
# соединения/DNS/фрагментация), выбирает доминирующую и выдаёт вероятную
# причину + эвристическую уверенность (%) + причины + рекомендации.

pktdiag timeline ./capture.pcapng
# UC-14: хронологическая лента событий (retransmission/dup ack/out-of-order/
# zero window/reset/dns error) с таймстампами и src:port -> dst:port.

pktdiag inspect ./capture.pcapng
# UC-20: быстрый чек-лист ✔/⚠ — MSS и Window Scale в SYN, Retransmission,
# Zero Window, Keepalive (TCP); Slow Response (DNS); Alerts (TLS).

pktdiag compare ./before.tar.zst ./after.tar.zst
# UC-13: таблица "до/после" по RTT, DNS, retransmission, resets, dropped,
# PPS и Health Score.

pktdiag health ./capture.pcapng
# Короткий вывод только Health Score с разбивкой по компонентам.
```

## Конфигурация (pktdiag.yaml)

`pktdiag capture` может брать параметры из YAML-файла (см. пример
`pktdiag.example.yaml`) — либо автоматически, если `./pktdiag.yaml`
существует в текущем каталоге, либо явно через `--config path.yaml`.
Явные флаги командной строки всегда переопределяют значения из конфига.

Это узкий самодельный парсер (`internal/yamlcfg`), а не полноценный YAML —
поддерживает только плоскую структуру "секция -> ключ: значение" без
списков и глубокой вложенности; для целей capture-конфига этого достаточно
(полноценный `gopkg.in/yaml.v3` недостижим — см. раздел про TUI ниже).

```bash
pktdiag capture                       # подхватит ./pktdiag.yaml, если есть
pktdiag capture --config prod.yaml
pktdiag capture --config prod.yaml --duration 10s   # duration переопределён явно
```

## Что уже есть

- Захват через `tcpdump` (интерфейс, BPF-фильтр, длительность, snaplen,
  ring buffer через `-C/-W`). При запуске от root добавляется `-Z root`,
  чтобы tcpdump не сбрасывал привилегии перед созданием следующих файлов
  кольца (иначе ротация падает с Permission denied на каталог результатов)
- Анализ ring buffer: после захвата файлы кольца (`capture.pcapngN`)
  находятся и склеиваются через `mergecap` в один pcap для полноценного
  анализа — проверено на реальной ротации (4/4 файла, ~3МБ трафика)
- YAML-конфиг для `capture` (`pktdiag.yaml`/`--config`) с приоритетом
  явных флагов над значениями из файла
- Сбор метаданных хоста без внешних зависимостей: uname, kernel, CPU, RAM,
  интерфейсы (`/proc/net/dev`, `/sys/class/net`), DNS (`/etc/resolv.conf`),
  таблица маршрутизации (`/proc/net/route`), правила `iptables`/`nftables`,
  выборка `conntrack`, ключевые сетевые параметры `sysctl`
- Анализ через `tshark`/`capinfos`: протоколы (TCP/UDP/ICMP/DNS/TLS/HTTP),
  TCP-метрики (retransmission/duplicate ACK/out-of-order/zero window/RST),
  RTT (avg/min/max по `tcp.analysis.ack_rtt`),
  DNS-метрики (запросы/ответы/среднее время/медленные/вероятные таймауты)
- Детектор аномалий с порогами (good/warning/critical) и эвристический
  Health Score (network/tcp/dns)
- Автоматический диагноз (`diagnose`) — группировка аномалий в вероятную
  причину с эвристической уверенностью
- Хронология событий (`timeline`), быстрый чек-лист (`inspect`),
  сравнение двух захватов (`compare`)
- Отчёты в JSON/HTML/Markdown/**PDF** (через `wkhtmltopdf`) + текстовая
  сводка для терминала
- Архивация результата в `capture-<дата>.tar.zst`
- Explain Engine — база знаний в `internal/explainx/data/explain.json`,
  легко расширяется новыми терминами

## Чего пока нет (следующая итерация)

- TUI (Bubble Tea) — **проверено и недостижимо в этой песочнице**: даже
  версия для Go 1.22 тянет `golang.org/x/sys`, а `golang.org` заблокирован
  сетевыми правилами (разрешён только `github.com`, но `go get` в direct-режиме
  всё равно резолвит `golang.org/x/...` через сам `golang.org`). Понадобится
  либо доступ к прокси Go-модулей/`golang.org`, либо vendoring зависимостей
  из другого окружения. Сейчас вместо интерактивных вкладок — `analyze`,
  `diagnose`, `timeline`, `inspect` с текстовым/HTML выводом.
  По той же причине конфиг читается самодельным парсером, а не
  `gopkg.in/yaml.v3`.
- Кроссплатформенность — часть sysinfo (`/proc`, `/sys`) linux-specific
- `conntrack`/`iptables`/`nftables` в metadata требуют root (уже есть
  в требованиях), на не-root хостах эти поля просто останутся пустыми
  с пометкой в `notes`

## Структура проекта

```
cmd/            обработчики CLI-команд (без cobra — вручную, т.к. сеть
                 в среде сборки блокирует транзитивную зависимость cobra)
internal/
  sysinfo/      сбор метаданных хоста (+ iptables/nft/conntrack/sysctl)
  capture/      обёртка над tcpdump
  analyze/      обёртка над tshark/capinfos + детектор аномалий + health score
                + diagnose/timeline/inspect
  report/       модель отчёта + рендер в JSON/HTML/MD/PDF
  archive/      упаковка в tar.zst
  doctorx/      проверки окружения
  explainx/     Explain Engine (база знаний в data/explain.json)
  yamlcfg/      минимальный парсер pktdiag.yaml
```
