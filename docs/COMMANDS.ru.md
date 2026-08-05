# Справочник команд

🇬🇧 [English version](COMMANDS.md)

Аргумент-источник для `report`, `analyze`, `diagnose`, `timeline`,
`inspect`, `compare` и `health` принимает одну из трёх форм:

- прямой путь к файлу `.pcap`/`.pcapng`
- каталог (pktdiag берёт первый найденный внутри `*.pcap`/`*.pcapng`)
- бандл `.tar.zst` от `pktdiag capture` (pktdiag распаковывает его во
  временный каталог автоматически, вместе с `metadata.json`, если он есть)

## pktdiag doctor

Проверяет окружение: наличие `tcpdump`, `dumpcap`, `tshark`, `capinfos`,
`mergecap`, `zstd`, `wkhtmltopdf`, `iptables`, `nft`, `conntrack`; текущие
права; свободное место на диске; доступные сетевые интерфейсы.
Отсутствие обязательного инструмента помечает проверку ✘ и блокирует
захват. Отсутствие опционального инструмента помечает её ⚠ и не блокирует
захват.

```
pktdiag doctor [флаги]

  --install    предложить установку недостающих пакетов, либо поставить
               их сразу с --yes
  --yes        не спрашивать подтверждения (используется с --install)
```

```bash
pktdiag doctor
pktdiag doctor --install
sudo pktdiag doctor --install --yes
```

Автоустановка поддерживает apt (Debian, Ubuntu) и требует root. На dnf,
yum, pacman, apk или brew `doctor` печатает эквивалентную команду для
ручной установки вместо того, чтобы её запускать. Если `apt-get update`
падает из-за недоступного стороннего репозитория, pktdiag выводит
предупреждение и всё равно запускает `apt-get install`: нужные pktdiag
пакеты обычно лежат в основных репозиториях дистрибутива.

## pktdiag capture

Запускает полный пайплайн: захват, сбор метаданных, анализ, отчёт, архив.

```
pktdiag capture [флаги]

  --iface STRING        сетевой интерфейс, по умолчанию автовыбор без lo
  --filter STRING       BPF-фильтр, например "tcp port 443"
  --duration STRING     например "30s", "5m". "0" запускает захват до Ctrl+C (по умолчанию 30s)
  --output DIR           каталог результатов, по умолчанию ./pktdiag-capture-<timestamp>
  --format LIST           форматы отчёта через запятую: html,json,md,pdf (по умолчанию html,json)
  --no-archive             не собирать финальный tar.zst
  --ring N                 включить кольцевой буфер: N файлов, 0 выключает его
  --ring-size MB            размер одного файла кольца в МБ (по умолчанию 100)
  --snaplen N                snapshot length tcpdump, 0 значит без ограничения (-s0)
  --max-size РАЗМЕР            остановить один файл при достижении размера, например "500MB", "2GB" (взаимоисключает --ring)
  --open                        открыть захват в Wireshark по завершении, нужно GUI-окружение
  --interactive                  пошагово спросить интерфейс, фильтр и длительность, игнорируя --iface/--filter/--duration
  --force                     продолжить, даже если doctor нашёл блокирующие (✘) проблемы
  --config PATH                 YAML-конфиг, по умолчанию ./pktdiag.yaml, если существует
```

Структура результата внутри `--output`:

```
capture.pcapng            сырой захват
metadata.json             снимок хоста: uname, cpu/ram, интерфейсы, маршруты,
                          dns, правила iptables/nftables, выборка conntrack, sysctl
report.json/html/md/pdf   по одному файлу на каждый запрошенный --format
```

pktdiag также пишет `<output-dir>.tar.zst` рядом с каталогом результатов,
если не передан `--no-archive`.

При `--ring N` pktdiag находит после захвата получившиеся файлы кольца
(`capture.pcapng0`, `capture.pcapng1` и так далее), сливает их через
`mergecap` в `capture.merged.pcapng` и анализирует именно объединённый
файл. Ring-buffer захваты получают полноценный анализ, а не только по
последнему файлу.

При запуске от root pktdiag добавляет `-Z root` к вызову `tcpdump`. Без
этого флага `tcpdump` на Debian и Ubuntu сбрасывает привилегии на
пользователя `tcpdump` сразу после открытия интерфейса. Этот
непривилегированный пользователь не может создавать новые файлы кольца
в каталоге, принадлежащем root, и захват падает посередине с `Permission
denied`.

```bash
pktdiag capture --iface eth0 --duration 5m
pktdiag capture --iface eth0 --filter "udp port 53" --duration 0
pktdiag capture --ring 5 --ring-size 50 --duration 10m
pktdiag capture --config prod.yaml --duration 10s
pktdiag capture --interactive
pktdiag capture --max-size 500MB
pktdiag capture --open
```

`--interactive` спрашивает интерфейс, фильтр и длительность по одному
вместо чтения `--iface`, `--filter` и `--duration`. Остальные флаги
(`--output`, `--format`, `--ring` и так далее) применяются как обычно
вместе с ним.

`--max-size` останавливает один выходной файл при достижении заданного
размера, без ротации на несколько файлов. Взаимоисключает `--ring`, у
которого свой лимит размера на файл через `--ring-size`. Размеры
используют десятичные единицы СИ (1MB = 1 000 000 байт), как у самого
флага `-C` в tcpdump.

`--open` запускает `wireshark` на готовом захвате и сразу возвращает
управление, не дожидаясь закрытия окна. Нужен установленный `wireshark`
и GUI-окружение (переменная `$DISPLAY` или `$WAYLAND_DISPLAY`); pktdiag
предупреждает, но не проваливает захват, если чего-то из этого не хватает.

## pktdiag report

Строит отчёт по уже существующему захвату без повторного захвата.

```
pktdiag report <источник> [флаги]

  --format LIST    html,json,md,pdf (по умолчанию html,json)
  --output DIR     куда сохранить отчёт, по умолчанию рядом с источником
```

```bash
pktdiag report ./capture.pcapng --format html,pdf
pktdiag report ./bundle.tar.zst --output ./out
```

## pktdiag analyze

Печатает текстовый обзор в терминал.

```
pktdiag analyze <источник> [флаги]

  --explain     напечатать полную статью Explain Engine для каждой
                найденной аномалии
  --save LIST    дополнительно сохранить файлы отчёта (html,json,md,pdf)
  --output DIR    куда сохранить --save, по умолчанию рядом с источником
```

```bash
pktdiag analyze ./bundle.tar.zst --explain
pktdiag analyze ./capture.pcapng --save json --output ./out
```

## pktdiag explain

Ищет термин в Explain Engine и печатает его пороги норма, warning,
critical, описание простым языком, типичные причины и рекомендации.
Запуск без аргумента печатает список всех известных терминов. Полный
список смотрите в [EXPLAIN.ru.md](EXPLAIN.ru.md).

```bash
pktdiag explain retransmission
pktdiag explain dns_slow
pktdiag explain
```

## pktdiag diagnose

Группирует все найденные аномалии по категориям (потери пакетов,
задержка, приёмный буфер, проблемы соединения, DNS, фрагментация),
выбирает доминирующую категорию и печатает вероятную причину с оценкой
уверенности, плюс причины и рекомендации из Explain Engine. Оценка
уверенности использует фиксированную эвристику, не модель: она суммирует вес
severity аномалий в выигравшей категории и ограничивает результат 96%.

```bash
pktdiag diagnose ./bundle.tar.zst
```

## pktdiag timeline

Печатает TCP- и DNS-события в хронологическом порядке: retransmission,
duplicate ACK, out-of-order, zero window, reset, DNS error response.
Каждая строка показывает время и `src:port -> dst:port`.

```bash
pktdiag timeline ./capture.pcapng
```

## pktdiag inspect

Печатает чек-лист: наличие MSS и Window Scale в SYN-пакетах, количество
ретрансмиссий, количество zero window, количество keepalive для TCP;
медленные ответы для DNS; alert-сообщения для TLS.

```bash
pktdiag inspect ./capture.pcapng
```

## pktdiag compare

Строит отчёты для двух захватов и печатает таблицу разницы: RTT, среднее
время ответа DNS, количество и процент ретрансмиссий, zero window,
резеты, отброшенные пакеты, средний PPS, Health Score.

```bash
pktdiag compare ./before.tar.zst ./after.tar.zst
```

## pktdiag health

Печатает только Health Score и разбивку по компонентам (network, tcp,
dns), для быстрой проверки или использования в скриптах.

```bash
pktdiag health ./capture.pcapng
```

## Форматы и схема отчёта

Каждый `report.json` имеет такую структуру (сокращено для краткости, точные
Go-структуры смотрите в [`internal/report/model.go`](../internal/report/model.go)):

```json
{
  "meta": { "generated_at": "...", "pktdiag_version": "0.1.0-mvp", "source": "capture.pcapng" },
  "capture": { "interface": "eth0", "filter": "tcp port 443", "packets_dropped_by_kernel": 0 },
  "summary": { "packets": 1245320, "duration_sec": 300.1, "avg_pps": 4150.2 },
  "protocols": { "tcp": 8000, "udp": 3000, "icmp": 50, "dns": 120, "tls": 4200, "http": 0 },
  "tcp": { "retransmissions": 124, "retransmission_pct": 8.4, "duplicate_acks": 40, "zero_window": 2, "resets": 5, "out_of_order": 12 },
  "rtt": { "samples": 340, "avg_ms": 12.4, "min_ms": 0.8, "max_ms": 210.3 },
  "deep": { "fragmented": 6, "syn_only": 1, "syn_ack": 1, "icmp_errors": 1 },
  "dns": { "queries": 120, "responses": 118, "avg_response_ms": 45.2, "slow_responses": 5, "likely_timeouts": 2 },
  "anomalies": [ { "id": "retransmission", "severity": "critical", "title": "TCP Retransmission", "value": "8.4%", "message": "..." } ],
  "health_score": { "total": 92, "components": { "network": 95, "tcp": 90, "dns": 88 } },
  "system": { "hostname": "...", "kernel": "...", "cpu_model": "...", "interfaces": [], "iptables_rules": [], "sysctl": {} }
}
```

`report.html` рендерит те же данные как самодостаточную статичную страницу
в тёмной теме. `report.md` даёт компактную сводку для вставки в тикет.
`report.pdf` конвертирует HTML-версию через `wkhtmltopdf`.
