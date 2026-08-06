# pktdiag

[![CI](https://github.com/FlexEbat/pktdiag/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/FlexEbat/pktdiag/actions/workflows/ci.yml)

pktdiag captures and analyzes network traffic from the command line. It
wraps `tcpdump` and `tshark`, collects host metadata alongside the
capture, detects anomalies against fixed thresholds, explains each one in
plain language, and produces a report in JSON, HTML, Markdown, or PDF.

🇷🇺 [Русская версия](README.ru.md) · [Full command reference](docs/COMMANDS.md) · [Explain Engine reference](docs/EXPLAIN.md)

## Why

Diagnosing a flaky network usually means capturing traffic with
`tcpdump`, opening it in Wireshark, hunting for retransmissions and
resets by hand, then explaining the result to someone who reads
Wireshark output less often than you do. pktdiag automates that:

- captures traffic and the host state around it in one command
- flags retransmissions, resets, zero windows, slow DNS, fragmentation,
  SYN floods, ICMP errors, and MTU mismatches against fixed thresholds
- scores the capture with a 0-100 Health Score, broken down by component
- explains any flagged issue, or any term you ask about, in plain language
- packages a capture into a single archive another person can analyze
  without rerunning anything

There is no GUI and no interactive wizard. Every command takes flags or a
YAML config file and runs to completion.

## Install

Requires `tcpdump`, `tshark` (which brings `capinfos` and `mergecap`),
and `zstd`. `wkhtmltopdf`, `iptables`, `nftables`, and `conntrack` are
optional; pktdiag skips the features that need them if they are missing.

```bash
sudo apt-get update
sudo apt-get install -y tcpdump tshark zstd
git clone https://github.com/FlexEbat/pktdiag.git
cd pktdiag
go build -o pktdiag .
```

`pktdiag doctor --install` installs missing packages for you on
Debian and Ubuntu. See [docs/COMMANDS.md](docs/COMMANDS.md#pktdiag-doctor).

## Usage

```bash
sudo ./pktdiag doctor
sudo ./pktdiag capture --iface eth0 --filter "tcp port 443" --duration 30s
./pktdiag analyze pktdiag-capture-*.tar.zst --explain
./pktdiag diagnose pktdiag-capture-*.tar.zst
```

`capture` writes a result directory with the raw pcap, host metadata,
and a report in your chosen formats, then archives it into a `.tar.zst`
bundle. Hand that bundle to anyone; `pktdiag analyze bundle.tar.zst`
reproduces the same picture without a second capture.

| Command | Does |
|---|---|
| `doctor` | Checks the environment, installs missing packages on request |
| `capture` | Runs the full pipeline: capture, metadata, analysis, report, archive |
| `report` | Builds a report from an existing capture |
| `analyze` | Prints a plain-text overview of an existing capture |
| `explain` | Explains a term: norm, causes, recommendations |
| `diagnose` | Picks the most likely cause among detected anomalies |
| `timeline` | Lists anomalies in chronological order |
| `inspect` | Prints a pass/fail checklist |
| `compare` | Diffs two captures |
| `health` | Prints only the Health Score |
| `tui` | Opens an interactive terminal viewer for one report |

Full flags and examples for every command: [docs/COMMANDS.md](docs/COMMANDS.md).

## Configuration

`pktdiag capture` reads defaults from `./pktdiag.yaml` if it exists, or
from a file passed via `--config`. Command-line flags always override the
config file. See [pktdiag.example.yaml](pktdiag.example.yaml) for a
template.

## Report formats

Every report is available as JSON (for scripts), HTML (a self-contained
dark-themed page), Markdown (for pasting into a ticket), or PDF (via
`wkhtmltopdf`). The JSON schema and a sample are documented in
[docs/COMMANDS.md](docs/COMMANDS.md#report-formats--schema).

## How it works

```
tcpdump + host metadata
        |
        v
tshark/capinfos (protocols, TCP quality, RTT, DNS)
gopacket (fragmentation, SYN flood, ICMP errors)
        |
        v
anomaly detection -> Health Score -> report (json/html/md/pdf)
        |
        v
capture-<date>.tar.zst
```

`capture` and analysis are separate stages on purpose. Capture on a
production host with no analysis tooling installed, then analyze the
resulting bundle anywhere.

## Development

```bash
go build ./...
go vet ./...
go test ./...
```

pktdiag depends on `github.com/google/gopacket` for packet-level
detectors that display filters cannot express, `github.com/spf13/cobra`
for command routing, and `github.com/spf13/viper` for reading
`pktdiag.yaml`. The sandbox this project was developed in blocks
`golang.org/x/*` at the network level, so builds involving these
dependencies run on GitHub Actions instead (`.github/workflows/ci.yml`),
which has normal internet access. The workflow regenerates
`go.mod`/`go.sum` with `go mod tidy` and commits them back, since a
correct `go.sum` also needs that same network access to produce.

If a build or test fails, the workflow commits the failure log to
`.ci/last-failure.log` and removes it once the build is green again.
GitHub's own log storage sits behind a domain this sandbox cannot reach
either, so the log travels through the one channel that already works:
a plain `git push`.

## License

[LICENSE](LICENSE)
