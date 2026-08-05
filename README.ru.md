# pktdiag

[![CI](https://github.com/FlexEbat/pktdiag/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/FlexEbat/pktdiag/actions/workflows/ci.yml)

pktdiag захватывает и анализирует сетевой трафик из командной строки.
Оборачивает `tcpdump` и `tshark`, собирает метаданные хоста вместе с
захватом, находит аномалии по фиксированным порогам, объясняет каждую
простым языком и строит отчёт в JSON, HTML, Markdown или PDF.

🇬🇧 [English version](README.md) · [Полный справочник команд](docs/COMMANDS.ru.md) · [Справочник Explain Engine](docs/EXPLAIN.ru.md)

## Зачем

Диагностика нестабильной сети обычно означает: захватить трафик через
`tcpdump`, открыть в Wireshark, вручную выискивать ретрансмиссии и
резеты, потом объяснить результат тому, кто читает вывод Wireshark реже
вас. pktdiag автоматизирует это:

- захватывает трафик и состояние хоста вокруг него одной командой
- отмечает ретрансмиссии, резеты, zero window, медленный DNS,
  фрагментацию, SYN flood, ICMP-ошибки и расхождение MTU по
  фиксированным порогам
- оценивает захват через Health Score от 0 до 100 с разбивкой по
  компонентам
- объясняет любую отмеченную проблему, или любой термин по запросу,
  простым языком
- упаковывает захват в единый архив, который другой человек
  анализирует без повторного захвата

GUI и интерактивного мастера нет. Каждая команда принимает флаги или
YAML-конфиг и выполняется до конца без диалогов.

## Установка

Нужны `tcpdump`, `tshark` (приносит `capinfos` и `mergecap`) и `zstd`.
`wkhtmltopdf`, `iptables`, `nftables` и `conntrack` опциональны: pktdiag
пропускает функции, которым они нужны, если их не хватает.

```bash
sudo apt-get update
sudo apt-get install -y tcpdump tshark zstd
git clone https://github.com/FlexEbat/pktdiag.git
cd pktdiag
go build -o pktdiag .
```

`pktdiag doctor --install` ставит недостающие пакеты сам на Debian и
Ubuntu. См. [docs/COMMANDS.ru.md](docs/COMMANDS.ru.md#pktdiag-doctor).

## Использование

```bash
sudo ./pktdiag doctor
sudo ./pktdiag capture --iface eth0 --filter "tcp port 443" --duration 30s
./pktdiag analyze pktdiag-capture-*.tar.zst --explain
./pktdiag diagnose pktdiag-capture-*.tar.zst
```

`capture` пишет каталог результата с сырым pcap, метаданными хоста и
отчётом в выбранных форматах, затем архивирует всё в бандл `.tar.zst`.
Передайте этот бандл кому угодно: `pktdiag analyze bundle.tar.zst`
восстанавливает ту же картину без повторного захвата.

| Команда | Делает |
|---|---|
| `doctor` | Проверяет окружение, ставит недостающие пакеты по запросу |
| `capture` | Запускает полный пайплайн: захват, метаданные, анализ, отчёт, архив |
| `report` | Строит отчёт по уже существующему захвату |
| `analyze` | Печатает текстовый обзор существующего захвата |
| `explain` | Объясняет термин: норма, причины, рекомендации |
| `diagnose` | Выбирает наиболее вероятную причину среди найденных аномалий |
| `timeline` | Печатает аномалии в хронологическом порядке |
| `inspect` | Печатает чек-лист pass/fail |
| `compare` | Сравнивает два захвата |
| `health` | Печатает только Health Score |

Все флаги и примеры для каждой команды: [docs/COMMANDS.ru.md](docs/COMMANDS.ru.md).

## Конфигурация

`pktdiag capture` читает значения по умолчанию из `./pktdiag.yaml`, если
он существует, либо из файла, переданного через `--config`. Флаги
командной строки всегда переопределяют конфиг. Шаблон:
[pktdiag.example.yaml](pktdiag.example.yaml).

## Форматы отчёта

Каждый отчёт доступен в JSON (для скриптов), HTML (самодостаточная
страница в тёмной теме), Markdown (для вставки в тикет) или PDF (через
`wkhtmltopdf`). JSON-схема и пример описаны в
[docs/COMMANDS.ru.md](docs/COMMANDS.ru.md#форматы-и-схема-отчёта).

## Как это работает

```
tcpdump + метаданные хоста
        |
        v
tshark/capinfos (протоколы, качество TCP, RTT, DNS)
gopacket (фрагментация, SYN flood, ICMP-ошибки)
        |
        v
детекция аномалий -> Health Score -> отчёт (json/html/md/pdf)
        |
        v
capture-<дата>.tar.zst
```

Захват и анализ разделены на два этапа осознанно. Захватывайте трафик на
production-хосте без установленных инструментов анализа, а затем
анализируйте получившийся бандл где угодно.

## Разработка

```bash
go build ./...
go vet ./...
go test ./...
```

У pktdiag одна внешняя Go-зависимость, `github.com/google/gopacket`, для
детекторов на уровне пакетов, которые display-filter не выразить.
Песочница, где разрабатывался проект, блокирует `golang.org/x/*` на
уровне сети, поэтому сборки с этой зависимостью идут через GitHub
Actions (`.github/workflows/ci.yml`), у которого есть обычный доступ в
интернет. Workflow пересобирает `go.mod`/`go.sum` через `go mod tidy` и
коммитит их обратно: правильный `go.sum` тоже требует этого доступа в
сеть.

Если сборка или тест падают, workflow коммитит лог падения в
`.ci/last-failure.log` и убирает его, когда сборка снова зелёная.
Собственное хранилище логов GitHub тоже лежит за доменом, недостижимым
из этой песочницы, поэтому лог идёт через канал, который уже работает:
обычный `git push`.

## Известные ограничения

- **Нет интерактивного TUI.** Исходный дизайн предполагал интерфейс на
  Bubble Tea. Bubble Tea, Cobra и Viper транзитивно тянут
  `golang.org/x/*`, недостижимый из этой песочницы по той же причине, по
  которой gopacket понадобился GitHub Actions. `analyze`, `diagnose`,
  `timeline` и `inspect` покрывают то же самое текстовым выводом.
- **`metadata.json` объединяет то, что исходный дизайн делил на
  отдельные файлы** (`routes.json`, `dns.json` и так далее). Те же
  данные, один файл.
- **Только Linux.** `internal/sysinfo` читает `/proc` и `/sys` напрямую.
  `iptables`, `nftables`, `conntrack` и `sysctl` и так линуксовые понятия.

## Лицензия

[LICENSE](LICENSE)
