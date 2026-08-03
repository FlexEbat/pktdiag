# pktdiag

**pktdiag** — CLI-инструмент для диагностики сети через захват и анализ
пакетов. Оборачивает `tcpdump`/`tshark`, автоматически собирает метаданные
хоста, находит аномалии, объясняет их простым языком и строит отчёты в
нескольких форматах (JSON/HTML/Markdown/PDF).

🇬🇧 [English version](README.md)

> **Статус: MVP.** Основной пайплайн (захват → анализ → отчёт → архив)
> полностью готов и протестирован на живом трафике. Что именно не
> реализовано относительно исходного ТЗ — см. раздел
> [Известные ограничения и roadmap](#известные-ограничения-и-roadmap).

---

## Оглавление

- [О проекте](#о-проекте)
- [Архитектура](#архитектура)
- [Требования](#требования)
- [Установка](#установка)
- [Сборка](#сборка)
- [Быстрый старт](#быстрый-старт)
- [Справочник команд](#справочник-команд)
  - [doctor](#pktdiag-doctor)
  - [capture](#pktdiag-capture)
  - [report](#pktdiag-report)
  - [analyze](#pktdiag-analyze)
  - [explain](#pktdiag-explain)
  - [diagnose](#pktdiag-diagnose)
  - [timeline](#pktdiag-timeline)
  - [inspect](#pktdiag-inspect)
  - [compare](#pktdiag-compare)
  - [health](#pktdiag-health)
- [Конфигурационный файл (pktdiag.yaml)](#конфигурационный-файл-pktdiagyaml)
- [Форматы и схема отчёта](#форматы-и-схема-отчёта)
- [Справочник Explain Engine](#справочник-explain-engine)
- [Собираемые метаданные](#собираемые-метаданные)
- [Структура проекта](#структура-проекта)
- [Известные ограничения и roadmap](#известные-ограничения-и-roadmap)
- [Устранение неполадок](#устранение-неполадок)
- [Лицензия](#лицензия)

---

## О проекте

Диагностика нестабильной сети обычно выглядит так: захватить трафик через
`tcpdump`, открыть в Wireshark, вручную выискивать ретрансмиссии/резеты/
медленный DNS, а потом ещё объяснить менее опытному коллеге, что всё это
значит. pktdiag автоматизирует рутинную часть этого процесса:

1. **Захватывает** трафик через `tcpdump`, параллельно собирая метаданные
   хоста (ядро, CPU/RAM, интерфейсы, маршруты, DNS-серверы, правила
   firewall, conntrack, sysctl).
2. **Анализирует** полученный pcap через `tshark`/`capinfos`: разбивка по
   протоколам, метрики качества TCP (ретрансмиссии, дубликаты ACK,
   переупорядочивание, zero window, резеты), RTT, время ответа DNS.
3. **Находит аномалии** по фиксированным порогам и превращает их в
   **Health Score** (0–100) с разбивкой по компонентам.
4. **Объясняет** любую найденную аномалию (или любой термин по запросу)
   простым языком: что это значит, типичные причины, что проверить дальше.
5. **Строит отчёт** в JSON (машиночитаемый), HTML (можно расшарить),
   Markdown (для тикетов/PR) или PDF (для тех, кому нужен именно PDF).
6. **Архивирует** всю сессию захвата в единый `tar.zst`-бандл, который
   можно передать кому угодно — тот запускает
   `pktdiag analyze bundle.tar.zst` и получает ту же картину без
   повторного захвата.

Всё работает из командной строки; GUI сознательно отсутствует.

## Архитектура

```
┌─────────────────────────────┐
│ pktdiag capture               │
│                                │
│ tcpdump  ───────────┐          │
│ метаданные (sysinfo)  │        │
│ tshark/capinfos ◄────┘         │
│ report.json/html/md/pdf        │
└──────────────┬─────────────────┘
               │
        capture-<дата>.tar.zst
               │
        (копируется куда угодно — повторный захват не нужен)
               │
┌──────────────▼──────────────────┐
│ pktdiag analyze / report /       │
│ diagnose / timeline / inspect /  │
│ compare / health / explain       │
└───────────────────────────────────┘
```

`capture` и `analyze` намеренно разделены на два этапа: можно захватывать
трафик на production-сервере без установленных инструментов анализа, а
затем передать бандл кому-то другому (или на свой ноутбук) для анализа.

## Требования

- Go 1.22+
- `tcpdump`, `tshark`, `capinfos` (из пакета `tshark`/`wireshark-common`),
  `zstd`, `tar` с поддержкой `--zstd`
- root, либо `CAP_NET_RAW`/`CAP_NET_ADMIN`, для захвата трафика
- опционально: `wkhtmltopdf` (для `--format pdf`),
  `iptables`/`nftables`/`conntrack` (для соответствующих секций
  `metadata.json` — при отсутствии просто пропускаются), `mergecap`
  (идёт вместе с `tshark`, нужен для анализа ring-buffer захватов)

## Установка

На Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y tcpdump tshark zstd wkhtmltopdf iptables nftables conntrack
```

`mergecap` и `capinfos` идут вместе с пакетом `tshark`, отдельно ставить
не нужно.

## Сборка

```bash
git clone https://github.com/FlexEbat/pktdiag.git
cd pktdiag
go build -o pktdiag .
```

У pktdiag **нулевые внешние Go-зависимости** — всё на стандартной
библиотеке плюс вызовы системных утилит (`tcpdump`, `tshark` и т.д.).
Почему — см. [Известные ограничения](#известные-ограничения-и-roadmap)
(коротко: среда сборки, использованная на этапе первоначальной
разработки, блокирует `golang.org/x/*`, от которого транзитивно зависит
почти любой сторонний Go-модуль — включая Cobra, Viper и Bubble Tea из
исходного предложения по стеку).

## Быстрый старт

```bash
# 1. Проверить, что окружение готово
sudo ./pktdiag doctor

# 2. Захватить 30 секунд трафика на eth0, отфильтровав по порту 443
sudo ./pktdiag capture --iface eth0 --filter "tcp port 443" --duration 30s

# -> создаст ./pktdiag-capture-<timestamp>/ с capture.pcapng,
#    metadata.json, report.json/html, и архив
#    capture-<timestamp>.tar.zst рядом.

# 3. Посмотреть, что произошло, простым языком
./pktdiag analyze pktdiag-capture-*.tar.zst --explain

# 4. Или сразу получить вероятный диагноз
./pktdiag diagnose pktdiag-capture-*.tar.zst
```

## Справочник команд

Общее замечание: для `report`/`analyze`/`diagnose`/`timeline`/`inspect`/
`compare`/`health` аргумент-источник может быть:
- прямым путём к `.pcap`/`.pcapng`,
- каталогом (используется первый найденный `*.pcap`/`*.pcapng`),
- бандлом `.tar.zst` от `pktdiag capture` (распаковывается во временный
  каталог автоматически, вместе с `metadata.json`, если он есть).

### `pktdiag doctor`

Проверяет готовность окружения к захвату: наличие
`tcpdump`/`dumpcap`/`tshark`/`capinfos`/`mergecap`/`zstd`/`wkhtmltopdf`/
`iptables`/`nft`/`conntrack`, текущие права (root или нет), свободное
место на диске, доступные сетевые интерфейсы. Возвращает ошибку, если
чего-то обязательного (✘) не хватает; отсутствие опциональных
инструментов помечается как ⚠ и не блокирует захват.

```
pktdiag doctor [флаги]

  --install    предложить (или, с --yes, сразу выполнить) автоустановку
               недостающих пакетов через обнаруженный пакетный менеджер
  --yes         не спрашивать подтверждения перед установкой (используется
                 с --install)
```

```bash
pktdiag doctor                    # только статус
pktdiag doctor --install          # статус, затем вопрос перед установкой
sudo pktdiag doctor --install --yes   # установить недостающее без вопросов
```

Автоустановка сейчас поддерживает только **apt** (Debian/Ubuntu) и требует
root. На других пакетных менеджерах (`dnf`/`yum`/`pacman`/`apk`/`brew`)
`doctor` определяет, какой из них есть, и вместо попытки установки
печатает эквивалентную команду для ручной установки — то же самое, если
apt есть, но нет root. Если `apt-get update` падает (например,
недоступен посторонний сторонний APT-репозиторий), pktdiag выводит
предупреждение и всё равно пробует `apt-get install` — нужные pktdiag
пакеты обычно идут из основных репозиториев дистрибутива, которые могли
обновиться успешно, даже если какой-то другой источник отвалился.

### `pktdiag capture`

Основной пайплайн: захват → метаданные → анализ → отчёт → архив.

```
pktdiag capture [флаги]

  --iface STRING        сетевой интерфейс (по умолчанию — автовыбор, не lo)
  --filter STRING       BPF-фильтр, например "tcp port 443"
  --duration STRING     например "30s", "5m"; "0" — до Ctrl+C (по умолчанию 30s)
  --output DIR           каталог результатов (по умолчанию ./pktdiag-capture-<timestamp>)
  --format LIST          форматы отчёта через запятую: html,json,md,pdf (по умолчанию html,json)
  --no-archive            не собирать финальный tar.zst
  --ring N                включить кольцевой буфер: N файлов (0 — выключено)
  --ring-size MB           размер одного файла кольца в МБ (по умолчанию 100)
  --snaplen N               snapshot length tcpdump (0 — без ограничения, -s0)
  --force                    продолжить, даже если doctor нашёл блокирующие (✘) проблемы
  --config PATH               YAML-конфиг (по умолчанию ./pktdiag.yaml, если существует)
```

Структура результата (в каталоге `--output`):

```
capture.pcapng         сырой захват
metadata.json           снимок хоста (uname, cpu/ram, интерфейсы, маршруты,
                         dns, правила iptables/nftables, выборка conntrack, sysctl)
report.json/html/md/pdf   по запрошенным --format
```

Плюс `<output-dir>.tar.zst` рядом, если не указан `--no-archive`.

При `--ring N` pktdiag после захвата ищет получившиеся файлы кольца
(`capture.pcapng0`, `capture.pcapng1`, ...), сливает их через `mergecap` в
`capture.merged.pcapng` и анализирует именно этот объединённый файл — то
есть ring-buffer захваты получают полноценный анализ, а не только по
последнему файлу.

При запуске от root pktdiag добавляет `-Z root` к вызову `tcpdump`. Это
важно именно для кольцевого буфера: по умолчанию `tcpdump` на
Debian/Ubuntu сбрасывает привилегии на пользователя `tcpdump` сразу после
открытия интерфейса, и этот непривилегированный пользователь не может
создавать новые файлы кольца в каталоге, принадлежащем root — захват
падает с `Permission denied` посередине процесса. `-Z root` отключает
сброс привилегий, раз мы и так уже root.

Примеры:

```bash
pktdiag capture --iface eth0 --duration 5m
pktdiag capture --iface eth0 --filter "udp port 53" --duration 0   # до Ctrl+C
pktdiag capture --ring 5 --ring-size 50 --duration 10m             # кольцевой буфер
pktdiag capture --config prod.yaml --duration 10s                  # флаг переопределяет конфиг
```

### `pktdiag report`

Строит отчёт по уже существующему захвату (pcap/каталог/бандл) без
повторного захвата.

```
pktdiag report <источник> [флаги]

  --format LIST    html,json,md,pdf (по умолчанию html,json)
  --output DIR     куда сохранить отчёт (по умолчанию — рядом с источником)
```

```bash
pktdiag report ./capture.pcapng --format html,pdf
pktdiag report ./bundle.tar.zst --output ./out
```

### `pktdiag analyze`

Печатает человекочитаемый обзор в терминал — ближайший аналог вкладки
"Overview" из исходной идеи с TUI, только без интерактивности.

```
pktdiag analyze <источник> [флаги]

  --explain          дополнительно вывести полную статью Explain Engine
                      для каждой найденной аномалии
  --save LIST          дополнительно сохранить файлы отчёта (html,json,md,pdf)
  --output DIR          куда сохранить --save (по умолчанию — рядом с источником)
```

```bash
pktdiag analyze ./bundle.tar.zst --explain
pktdiag analyze ./capture.pcapng --save json --output ./out
```

### `pktdiag explain`

Ищет термин в Explain Engine и выводит его пороги
норма/warning/critical, описание простым языком, типичные причины и
рекомендации. Без аргумента — выводит список всех известных терминов. Полный
список — в разделе [Справочник Explain Engine](#справочник-explain-engine)
ниже.

```bash
pktdiag explain retransmission
pktdiag explain dns_slow
pktdiag explain     # список всех терминов
```

### `pktdiag diagnose`

«Самая сильная фича» из исходного ТЗ (UC-19): группирует все найденные
аномалии по категориям (потери пакетов / задержка / приёмный буфер /
проблемы соединения / DNS / фрагментация), выбирает доминирующую
категорию и выдаёт вероятную причину с эвристической оценкой уверенности,
плюс объединённые причины и рекомендации из Explain Engine.

Это rule-based эвристика, а не ML — уверенность выводится из
взвешенной по severity суммы аномалий в выигравшей категории, с потолком
в 96%.

```bash
pktdiag diagnose ./bundle.tar.zst
```

```
Вероятная причина
  Проблемы установления/поддержания соединений

Уверенность
  62%

Сигналы
  • TCP Reset — 3

Возможные причины
  • Сервис или порт недоступны
  • Firewall блокирует и сбрасывает соединение
  ...
```

### `pktdiag timeline`

Хронологический список интересных TCP/DNS-событий (retransmission,
duplicate ACK, out-of-order, zero window, reset, DNS error responses) с
таймстампами и `src:port -> dst:port`.

```bash
pktdiag timeline ./capture.pcapng
```

### `pktdiag inspect`

Быстрый чек-лист ✔/⚠: наличие MSS и Window Scale в SYN-пакетах,
количество ретрансмиссий, количество zero window, количество keepalive
(TCP); медленные ответы (DNS); TLS alert-сообщения (TLS).

```bash
pktdiag inspect ./capture.pcapng
```

### `pktdiag compare`

Строит отчёты для двух захватов («до»/«после») и выводит таблицу разницы:
RTT, среднее время ответа DNS, количество/процент ретрансмиссий, zero
window, резеты, отброшенные пакеты, средний PPS, Health Score.

```bash
pktdiag compare ./before.tar.zst ./after.tar.zst
```

### `pktdiag health`

Только Health Score с разбивкой по компонентам (network/tcp/dns), без
остального отчёта — для быстрой проверки или использования в скриптах.

```bash
pktdiag health ./capture.pcapng
```

## Конфигурационный файл (pktdiag.yaml)

`pktdiag capture` может брать значения по умолчанию из YAML-файла — либо
автоматически, если `./pktdiag.yaml` существует в текущем каталоге, либо
явно через `--config path.yaml`. **Явные флаги командной строки всегда
приоритетнее** значений из конфига.

```yaml
capture:
  iface: eth0
  filter: "tcp port 443"
  duration: 60s
  output: ""        # пусто — автоматическое имя pktdiag-capture-<timestamp>
  ring: 0            # 0 — кольцевой буфер выключен
  ring_size: 100     # МБ на файл кольца, если ring > 0
  snaplen: 0         # 0 — без ограничения (-s0)

report:
  format: html,json  # можно добавить md,pdf
  archive: true       # false — не собирать tar.zst
```

Готовый шаблон для копирования — [`pktdiag.example.yaml`](pktdiag.example.yaml)
в этом репозитории.

> **О реализации:** это *не* полноценный YAML-парсер. Это узкий
> самодельный парсер (`internal/yamlcfg`), который понимает только
> плоскую двухуровневую структуру, показанную выше — без списков, без
> глубокой вложенности, без якорей. Настоящей YAML-библиотеке
> (`gopkg.in/yaml.v3`) понадобился бы `golang.org/x/...`, который
> недостижим из среды сборки, использованной на этапе первоначальной
> разработки (см. [Известные ограничения](#известные-ограничения-и-roadmap)).
> Если собирать pktdiag там, где есть обычный доступ в интернет,
> подключение настоящего YAML-парсера — небольшое, локализованное
> изменение.

## Форматы и схема отчёта

Каждый отчёт (`report.json`) имеет такую структуру (поля сокращены для
краткости — точные Go-структуры см. в `internal/report/model.go`):

```json
{
  "meta": { "generated_at": "...", "pktdiag_version": "0.1.0-mvp", "source": "capture.pcapng" },
  "capture": { "interface": "eth0", "filter": "tcp port 443", "packets_dropped_by_kernel": 0 },
  "summary": { "packets": 1245320, "duration_sec": 300.1, "avg_pps": 4150.2 },
  "protocols": { "tcp": 8000, "udp": 3000, "icmp": 50, "dns": 120, "tls": 4200, "http": 0 },
  "tcp": { "retransmissions": 124, "retransmission_pct": 8.4, "duplicate_acks": 40, "zero_window": 2, "resets": 5, "out_of_order": 12 },
  "rtt": { "samples": 340, "avg_ms": 12.4, "min_ms": 0.8, "max_ms": 210.3 },
  "dns": { "queries": 120, "responses": 118, "avg_response_ms": 45.2, "slow_responses": 5, "likely_timeouts": 2 },
  "anomalies": [ { "id": "retransmission", "severity": "critical", "title": "TCP Retransmission", "value": "8.4%", "message": "..." } ],
  "health_score": { "total": 92, "components": { "network": 95, "tcp": 90, "dns": 88 } },
  "system": { "hostname": "...", "kernel": "...", "cpu_model": "...", "interfaces": [], "iptables_rules": [], "sysctl": {} }
}
```

`report.html` рендерит те же данные как самодостаточную статичную
страницу в тёмной теме. `report.md` — компактная markdown-сводка, удобная
для вставки в тикет. `report.pdf` — та же HTML-версия, сконвертированная
через `wkhtmltopdf`.

## Справочник Explain Engine

`pktdiag explain <термин>` (или `--explain` у `analyze`/`diagnose`) ищет
один из этих терминов (алиасы в скобках):

| Термин | Что покрывает |
|---|---|
| `retransmission` (`tcp.retransmission`) | TCP-сегменты, отправленные повторно из-за отсутствия ACK вовремя |
| `duplicate_ack` | Получатель повторно подтверждает один и тот же байт — обычно означает пропущенный сегмент |
| `out_of_order` | Пакеты приходят не в порядке отправки |
| `zero_window` | Буфер получателя переполнен, отправителю велено приостановиться |
| `rst` (`tcp.reset`) | Соединение принудительно сброшено вместо штатного закрытия через FIN |
| `rtt` | Время кругового пути и что обычно означает его резкий рост |
| `dns_timeout` | DNS-запрос отправлен, ответ не получен |
| `dns_slow` | DNS-ответ пришёл, но медленно |
| `syn_flood` | Большой объём SYN без ответа — DoS или недоступный сервис |
| `fragmentation` | IP-пакеты дробятся, так как превышают MTU по пути |
| `packets_dropped` | Ядро отбросило пакеты *во время захвата* (буфер/диск не успевают) |
| `bandwidth` (`throughput`) | Средняя скорость передачи данных за время захвата |
| `pps` (`packets per second`) | Среднее количество пакетов в секунду за время захвата |

Каждая статья включает: пороги норма/warning/critical, описание простым
языком, типичные причины и рекомендации. Полный источник —
[`internal/explainx/data/explain.json`](internal/explainx/data/explain.json)
— добавление нового термина — это просто новый JSON-объект в этом файле.

## Собираемые метаданные

`metadata.json` (записывается перед началом захвата) включает:

- `hostname`, `uname`, `kernel`, `os`, `arch`
- `cpu_model`, `cpu_count`, `mem_total_kb`
- `interfaces` — имя, MAC, состояние, MTU, счётчики RX/TX-байт
  (из `/proc/net/dev`, `/sys/class/net`)
- `dns_servers` — из `/etc/resolv.conf`
- `routes_raw` — сырые строки `/proc/net/route`
- `iptables_rules` — вывод `iptables -S` по таблицам `filter`/`nat`/`mangle`
- `nftables_ruleset` — `nft list ruleset`
- `conntrack_sample` — до 200 строк `conntrack -L` (не полный дамп на
  нагруженных хостах)
- `sysctl` — фиксированный набор сетевых параметров ядра
  (`net.core.rmem_max`, `net.ipv4.tcp_congestion_control` и т.д.)
- `notes` — всё, что не удалось собрать, и почему (например, нет
  утилиты, нет прав) — захват из-за этого никогда не прерывается, просто
  логируется здесь

Всё это собирается без сторонних зависимостей: вызовы `exec.Command` к
системным утилитам плюс чтение `/proc` и `/etc`.

## Структура проекта

```
cmd/                 обработчики CLI-команд (без Cobra — см. Известные ограничения)
internal/
  sysinfo/            сбор метаданных хоста (uname/cpu/ram/интерфейсы/
                       маршруты/dns/iptables/nftables/conntrack/sysctl)
  capture/             обёртка над tcpdump, поиск и слияние файлов ring buffer
  analyze/             обёртка над tshark/capinfos, детектор аномалий,
                        health score, логика diagnose/timeline/inspect
  report/               модель отчёта + рендер в JSON/HTML/Markdown/PDF
  archive/               упаковка в tar.zst
  doctorx/               проверки окружения
  explainx/               Explain Engine (база знаний в data/explain.json)
  yamlcfg/                 минимальный парсер pktdiag.yaml
```

## Известные ограничения и roadmap

По сравнению с исходным ТЗ (`pktdiag.md`), не реализовано следующее — в
основном по одной конкретной, проверенной причине:

- **Интерактивный TUI (`pktdiag tui`)** — исходное предложение по стеку
  использовало Bubble Tea. **Подтверждённо недостижимо** в среде, где
  проект изначально разрабатывался: даже совместимая с Go 1.22 версия
  Bubble Tea транзитивно требует `golang.org/x/sys`, а сам `golang.org`
  заблокирован сетевыми правилами (разрешены только
  `github.com`/`codeload.github.com`, а разрешению модулей Go для
  пакетов `golang.org/x/...` нужен прямой доступ к `golang.org` для
  определения VCS root — `go get` падает с `403 Forbidden: Host not in
  allowlist: golang.org`). То же самое касается Cobra, Viper и любой
  YAML-библиотеки — отсюда самодельные замены на stdlib по всему
  проекту. Если собирать где-то с обычным доступом в интернет, подключить
  их обратно — несложная задача.
- **Интерактивный мастер захвата** (пошаговое меню выбора
  интерфейса/фильтра/длительности) — заменён на флаги + YAML-конфиг.
- **`--open`** (автозапуск Wireshark после захвата) — сознательно
  пропущено по явному требованию «без GUI» на этапе разработки.
- **Детекторы MTU mismatch, SYN flood и IP-фрагментации** — в Explain
  Engine есть статьи `syn_flood` и `fragmentation`, но автоматического
  обнаружения этих паттернов в pcap пока нет (в отличие от
  retransmission/duplicate-ack/out-of-order/zero-window/reset/RTT/DNS,
  которые обнаруживаются автоматически).
- **Проверка ICMP-ошибок** — не реализована.
- **Остановка захвата в один файл по фиксированному размеру** (UC-03 из
  исходного ТЗ, «стоп после N ГБ») — есть только ограничение размера для
  ring buffer (`--ring-size`); отдельного флага «остановить этот один
  файл на N ГБ» без кольца нет.
- **Отдельные файлы бандла** (`routes.json`, `dns.json`, `iptables.json`,
  `conntrack.json` по отдельности, как в исходном UC-07) — вместо этого
  всё объединено в один `metadata.json`. Функционально эквивалентно,
  структурно отличается от ТЗ.
- **`pktdiag anomalies`** и **`pktdiag export`** как отдельные названия
  команд — функциональность есть (аномалии выводятся в каждом отчёте/
  `analyze`/`diagnose`; экспорт в формат — это `report --format`), просто
  не под этими конкретными именами команд.
- **Кроссплатформенность** — `internal/sysinfo` читает `/proc` и `/sys`
  напрямую; это сознательно только для Linux (само исходное ТЗ
  ориентировано на Linux — `iptables`/`nft`/`conntrack`/`sysctl` — это
  линуксовые понятия).

## Устранение неполадок

**`tcpdump: <file>: Permission denied` при захвате с ring buffer.**
Починено в изменении «анализ ring buffer» — pktdiag теперь передаёт
`-Z root` в `tcpdump` при запуске от root, что не даёт ему сбросить
привилегии перед созданием файлов ротации. Если запуск *не* от root и
ошибка всё равно возникает — непривилегированному пользователю захвата
(часто `tcpdump` на Debian/Ubuntu) нужны права на запись в каталог
результатов.

**`doctor` показывает ✘ для `tcpdump`/`tshark`.** Установите их (см.
[Установку](#установка)). Отсутствие `dumpcap`/`capinfos`/`zstd`/
`wkhtmltopdf` показывается только как ⚠ (опционально) и не блокирует
захват, кроме `zstd` — он нужен для финального шага архивации
(пропускается через `--no-archive`).

**`report --format pdf` падает с «wkhtmltopdf не найден».** Установите
пакет `wkhtmltopdf`; экспорт в PDF вызывает его как внешнюю утилиту.

**Анализ ring buffer говорит «файлы с числовым суффиксом не найдены».**
Такое бывает, если кольцо ни разу не провернулось (трафик за весь захват
не превысил `--ring-size`) — проверьте `<output>/capture.pcapng` без
числового суффикса и проанализируйте его напрямую через `pktdiag report`.

## Лицензия

См. [LICENSE](LICENSE).
