# pktdiag

**pktdiag** is a CLI tool for network diagnostics through packet capture and
analysis. It wraps `tcpdump`/`tshark` with automatic metadata collection,
anomaly detection, plain-language explanations of what went wrong, and
multi-format reporting (JSON/HTML/Markdown/PDF).

🇷🇺 [Русская версия](README.ru.md)

> **Status: MVP.** Core pipeline (capture → analyze → report → archive) is
> complete and tested against live traffic. See [Known Limitations & Roadmap](#known-limitations--roadmap)
> for what's missing relative to the original spec.

---

## Table of contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Build](#build)
- [Quick start](#quick-start)
- [Command reference](#command-reference)
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
- [Configuration file (pktdiag.yaml)](#configuration-file-pktdiagyaml)
- [Report formats & schema](#report-formats--schema)
- [Explain Engine reference](#explain-engine-reference)
- [Collected metadata](#collected-metadata)
- [Project structure](#project-structure)
- [Known limitations & roadmap](#known-limitations--roadmap)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

Diagnosing a flaky network usually means: capture traffic with `tcpdump`,
open it in Wireshark, manually hunt for retransmissions/resets/slow DNS,
and then explain to someone less familiar with networking what any of that
means. pktdiag automates the repetitive parts of that workflow:

1. **Capture** traffic with `tcpdump`, while collecting host metadata
   (kernel, CPU/RAM, interfaces, routes, DNS servers, firewall rules,
   conntrack, sysctl) in parallel.
2. **Analyze** the resulting pcap via `tshark`/`capinfos`: protocol
   breakdown, TCP quality metrics (retransmissions, duplicate ACKs,
   out-of-order, zero window, resets), RTT, DNS response times.
3. **Detect anomalies** against fixed thresholds and turn them into a
   **Health Score** (0-100) with a per-component breakdown.
4. **Explain** any detected anomaly (or any term you ask about) in plain
   language: what it means, typical causes, what to check next.
5. **Report** everything as JSON (machine-readable), HTML (shareable),
   Markdown (for tickets/PRs), or PDF (for people who want a PDF).
6. **Archive** the whole capture session into a single `tar.zst` bundle
   you can hand off to someone else, who runs `pktdiag analyze bundle.tar.zst`
   and gets the same picture without re-running anything.

Everything runs from the command line; there is intentionally no GUI.

## Architecture

```
┌─────────────────────────────┐
│ pktdiag capture               │
│                                │
│ tcpdump  ───────────┐          │
│ metadata (sysinfo)   │         │
│ tshark/capinfos ◄────┘         │
│ report.json/html/md/pdf        │
└──────────────┬─────────────────┘
               │
        capture-<date>.tar.zst
               │
        (copy anywhere — no re-capture needed)
               │
┌──────────────▼──────────────────┐
│ pktdiag analyze / report /       │
│ diagnose / timeline / inspect /  │
│ compare / health / explain       │
└───────────────────────────────────┘
```

`capture` and `analyze` are deliberately separate stages: you can capture
on a production box with no analysis tooling installed, then hand the
bundle to someone else (or your own laptop) for analysis.

## Requirements

- Go 1.22+
- `tcpdump`, `tshark`, `capinfos` (from the `tshark`/`wireshark-common`
  package), `zstd`, `tar` with `--zstd` support
- root, or `CAP_NET_RAW`/`CAP_NET_ADMIN`, to capture traffic
- optional: `wkhtmltopdf` (for `--format pdf`), `iptables`/`nftables`/`conntrack`
  (for the corresponding `metadata.json` sections — silently skipped if
  absent), `mergecap` (bundled with `tshark`, needed to analyze ring-buffer
  captures)

## Installation

On Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y tcpdump tshark zstd wkhtmltopdf iptables nftables conntrack
```

`mergecap` and `capinfos` come with the `tshark` package, no extra install
needed.

## Build

```bash
git clone https://github.com/FlexEbat/pktdiag.git
cd pktdiag
go build -o pktdiag .
```

pktdiag has **zero external Go dependencies** — everything is standard
library plus calls out to system tools (`tcpdump`, `tshark`, etc). See
[Known Limitations](#known-limitations--roadmap) for why (short version:
the build environment used during initial development blocks
`golang.org/x/*`, which almost every third-party Go module transitively
depends on — including Cobra, Viper, and Bubble Tea from the original
tech-stack proposal).

## Quick start

```bash
# 1. Check the environment is ready
sudo ./pktdiag doctor

# 2. Capture 30 seconds of traffic on eth0, filtered to port 443
sudo ./pktdiag capture --iface eth0 --filter "tcp port 443" --duration 30s

# -> produces ./pktdiag-capture-<timestamp>/ with capture.pcapng,
#    metadata.json, report.json/html, and a capture-<timestamp>.tar.zst
#    archive next to it.

# 3. Look at what happened, in plain language
./pktdiag analyze pktdiag-capture-*.tar.zst --explain

# 4. Or get a straight probable-cause diagnosis
./pktdiag diagnose pktdiag-capture-*.tar.zst
```

## Command reference

Global note: for `report`/`analyze`/`diagnose`/`timeline`/`inspect`/`compare`/`health`,
the "source" argument accepts any of:
- a `.pcap`/`.pcapng` file directly,
- a directory (the first `*.pcap`/`*.pcapng` found inside is used),
- a `.tar.zst` bundle produced by `pktdiag capture` (extracted to a temp
  dir automatically, including `metadata.json` if present).

### `pktdiag doctor`

Checks that the environment is ready to capture: presence of
`tcpdump`/`dumpcap`/`tshark`/`capinfos`/`zstd`/`wkhtmltopdf`, effective
permissions (root or not), free disk space, and available network
interfaces. Fails (via error return) if anything required (✘) is missing;
optional tools missing show as ⚠ and don't block capture.

```bash
pktdiag doctor
```

### `pktdiag capture`

The main pipeline: capture → metadata → analyze → report → archive.

```
pktdiag capture [flags]

  --iface STRING        network interface (default: auto-picked, skips lo)
  --filter STRING       BPF filter, e.g. "tcp port 443"
  --duration STRING     e.g. "30s", "5m"; "0" = capture until Ctrl+C (default 30s)
  --output DIR          results directory (default ./pktdiag-capture-<timestamp>)
  --format LIST         comma-separated report formats: html,json,md,pdf (default html,json)
  --no-archive          skip building the final tar.zst
  --ring N              enable ring buffer with N files (0 = disabled)
  --ring-size MB        size per ring file in MB (default 100)
  --snaplen N            tcpdump snapshot length (0 = unlimited, -s0)
  --force                proceed even if `doctor` found blocking (✘) issues
  --config PATH          YAML config file (default ./pktdiag.yaml if present)
```

Output layout (in `--output` dir):

```
capture.pcapng        raw capture
metadata.json          host snapshot (uname, cpu/ram, interfaces, routes,
                        dns, iptables/nftables rules, conntrack sample, sysctl)
report.json/html/md/pdf   per requested --format
```

Plus `<output-dir>.tar.zst` next to it, unless `--no-archive`.

If `--ring N` is used, pktdiag looks for the resulting ring files
(`capture.pcapng0`, `capture.pcapng1`, ...) after capture, merges them with
`mergecap` into `capture.merged.pcapng`, and analyzes that merged file —
so ring-buffer captures get full analysis, not just the last file.

When run as root, pktdiag adds `-Z root` to the `tcpdump` invocation. This
matters specifically for ring buffer: by default `tcpdump` on
Debian/Ubuntu drops privileges to the `tcpdump` user right after opening
the interface, and the unprivileged user then can't create new ring files
in a directory owned by root — capture fails with `Permission denied`
partway through. `-Z root` disables the privilege drop since we're already
root.

Examples:

```bash
pktdiag capture --iface eth0 --duration 5m
pktdiag capture --iface eth0 --filter "udp port 53" --duration 0   # until Ctrl+C
pktdiag capture --ring 5 --ring-size 50 --duration 10m             # ring buffer
pktdiag capture --config prod.yaml --duration 10s                  # flag overrides config
```

### `pktdiag report`

Builds a report from an existing capture (pcap/dir/bundle) without
re-capturing.

```
pktdiag report <source> [flags]

  --format LIST    html,json,md,pdf (default html,json)
  --output DIR     where to write the report (default: next to the source)
```

```bash
pktdiag report ./capture.pcapng --format html,pdf
pktdiag report ./bundle.tar.zst --output ./out
```

### `pktdiag analyze`

Prints a human-readable overview to the terminal — the closest thing to
the "Overview" tab from the original TUI concept, minus the interactivity.

```
pktdiag analyze <source> [flags]

  --explain         also print the full Explain Engine entry for every
                     detected anomaly
  --save LIST        additionally write report files (html,json,md,pdf)
  --output DIR        where to write --save output (default: next to source)
```

```bash
pktdiag analyze ./bundle.tar.zst --explain
pktdiag analyze ./capture.pcapng --save json --output ./out
```

### `pktdiag explain`

Looks up a term in the Explain Engine and prints its norm/warning/critical
thresholds, plain-language description, likely causes, and
recommendations. Run with no argument to list all known terms. See
[Explain Engine reference](#explain-engine-reference) below for the full
list.

```bash
pktdiag explain retransmission
pktdiag explain dns_slow
pktdiag explain     # lists all terms
```

### `pktdiag diagnose`

The "strongest feature" from the original spec (UC-19): groups all
detected anomalies into categories (packet loss / latency / receive
buffer / connection issues / DNS / fragmentation), picks the dominant
category, and reports a probable cause with a heuristic confidence score,
plus the aggregated causes and recommendations from the Explain Engine.

This is a rule-based heuristic, not ML — confidence is derived from the
severity-weighted sum of anomalies in the winning category, capped at 96%.

```bash
pktdiag diagnose ./bundle.tar.zst
```

```
Probable cause
  Connection establishment/keepalive issues

Confidence
  62%

Signals
  • TCP Reset — 3

Possible causes
  • Service or port unreachable
  • Firewall blocking and resetting the connection
  ...
```

### `pktdiag timeline`

Chronological list of interesting TCP/DNS events (retransmission,
duplicate ACK, out-of-order, zero window, reset, DNS error responses)
with timestamps and `src:port -> dst:port`.

```bash
pktdiag timeline ./capture.pcapng
```

### `pktdiag inspect`

Fast ✔/⚠ checklist: MSS and Window Scale presence in SYN packets,
retransmission count, zero window count, keepalive count (TCP); slow
responses (DNS); TLS alert messages (TLS).

```bash
pktdiag inspect ./capture.pcapng
```

### `pktdiag compare`

Builds reports for two captures ("before"/"after") and prints a diff
table: RTT, DNS avg response time, retransmission count/%, zero window,
resets, dropped packets, avg PPS, Health Score.

```bash
pktdiag compare ./before.tar.zst ./after.tar.zst
```

### `pktdiag health`

Just the Health Score and its component breakdown (network/tcp/dns),
without the rest of the report — for quick checks or scripting.

```bash
pktdiag health ./capture.pcapng
```

## Configuration file (pktdiag.yaml)

`pktdiag capture` can read defaults from a YAML file — automatically, if
`./pktdiag.yaml` exists in the current directory, or explicitly via
`--config path.yaml`. **Explicit command-line flags always win** over
values from the config file.

```yaml
capture:
  iface: eth0
  filter: "tcp port 443"
  duration: 60s
  output: ""        # empty = auto-named pktdiag-capture-<timestamp>
  ring: 0            # 0 = ring buffer disabled
  ring_size: 100     # MB per ring file, if ring > 0
  snaplen: 0         # 0 = unlimited (-s0)

report:
  format: html,json  # can add md,pdf
  archive: true       # false = skip tar.zst
```

See [`pktdiag.example.yaml`](pktdiag.example.yaml) in this repo for a
ready-to-copy template.

> **Note on implementation:** this is *not* a full YAML parser. It's a
> narrow, hand-written parser (`internal/yamlcfg`) that only understands
> the flat two-level structure shown above — no lists, no deep nesting, no
> anchors. A real YAML library (`gopkg.in/yaml.v3`) would need
> `golang.org/x/...`, which the build environment used during initial
> development can't reach (see [Known Limitations](#known-limitations--roadmap)).
> If you build pktdiag somewhere with normal internet access, swapping in
> a real YAML parser is a small, self-contained change.

## Report formats & schema

Every report (`report.json`) follows this shape (fields trimmed for
brevity — see `internal/report/model.go` for the exact Go structs):

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

`report.html` renders the same data as a dark-themed, self-contained
static page. `report.md` is a compact Markdown summary suitable for
pasting into a ticket. `report.pdf` is the HTML version converted via
`wkhtmltopdf`.

## Explain Engine reference

`pktdiag explain <term>` (or `--explain` on `analyze`/`diagnose`) looks up
one of these terms (aliases in parentheses):

| Term | What it covers |
|---|---|
| `retransmission` (`tcp.retransmission`) | TCP segments re-sent because no ACK arrived in time |
| `duplicate_ack` | Receiver re-acknowledging the same byte — usually a missing segment |
| `out_of_order` | Packets arriving out of send order |
| `zero_window` | Receiver's buffer full, sender told to pause |
| `rst` (`tcp.reset`) | Connection forcibly reset instead of a clean FIN close |
| `rtt` | Round-trip time and what a jump in it usually means |
| `dns_timeout` | DNS query sent with no response received |
| `dns_slow` | DNS response arrived, but slowly |
| `syn_flood` | Large volume of unanswered SYNs — DoS or unreachable service |
| `fragmentation` | IP packets split because they exceed path MTU |
| `packets_dropped` | Kernel dropped packets *during capture* (buffer/disk too slow) |
| `bandwidth` (`throughput`) | Average data rate over the capture |
| `pps` (`packets per second`) | Average packet rate over the capture |

Each entry includes: good/warning/critical thresholds, a plain-language
description, typical causes, and recommendations. The full source is
[`internal/explainx/data/explain.json`](internal/explainx/data/explain.json)
— adding a new term is just adding a new JSON object to that file.

## Collected metadata

`metadata.json` (written before capture starts) includes:

- `hostname`, `uname`, `kernel`, `os`, `arch`
- `cpu_model`, `cpu_count`, `mem_total_kb`
- `interfaces` — name, MAC, state, MTU, RX/TX byte counters (from `/proc/net/dev`, `/sys/class/net`)
- `dns_servers` — from `/etc/resolv.conf`
- `routes_raw` — raw `/proc/net/route` lines
- `iptables_rules` — `iptables -S` output for `filter`/`nat`/`mangle` tables
- `nftables_ruleset` — `nft list ruleset`
- `conntrack_sample` — up to 200 lines of `conntrack -L` (not a full dump on busy hosts)
- `sysctl` — a fixed set of network-relevant kernel parameters (`net.core.rmem_max`, `net.ipv4.tcp_congestion_control`, etc.)
- `notes` — anything that failed to collect and why (e.g. missing tool, no permission) — capture never aborts because of this, it just gets logged here

All of this is collected without any third-party dependency: `exec.Command`
calls to system tools, plus reads from `/proc` and `/etc`.

## Project structure

```
cmd/                CLI command handlers (no Cobra — see Known Limitations)
internal/
  sysinfo/           host metadata collection (uname/cpu/ram/interfaces/
                      routes/dns/iptables/nftables/conntrack/sysctl)
  capture/           tcpdump wrapper, ring-buffer file discovery + merge
  analyze/           tshark/capinfos wrapper, anomaly detector, health
                      score, diagnose/timeline/inspect logic
  report/            report model + JSON/HTML/Markdown/PDF rendering
  archive/            tar.zst packing
  doctorx/            environment checks
  explainx/            Explain Engine (knowledge base in data/explain.json)
  yamlcfg/             minimal pktdiag.yaml parser
```

## Known limitations & roadmap

Compared to the original spec (`pktdiag.md`), the following is **not**
implemented, mostly for one specific, verified reason:

- **Interactive TUI (`pktdiag tui`)** — the original stack proposal used
  Bubble Tea. **Confirmed unreachable** in the environment this was first
  built in: even a Go-1.22-compatible Bubble Tea version transitively
  requires `golang.org/x/sys`, and `golang.org` itself is blocked by
  network egress rules (only `github.com`/`codeload.github.com` are
  allowed, and Go's module resolution for `golang.org/x/...` packages
  needs to reach `golang.org` directly to resolve the VCS root — `go get`
  fails with `403 Forbidden: Host not in allowlist: golang.org`). The same
  applies to Cobra, Viper, and any YAML library — hence the hand-rolled
  stdlib-only replacements throughout this project. If you build
  somewhere with normal internet access, swapping these in is
  straightforward.
- **Interactive capture wizard** (step-by-step interface/filter/duration
  menu) — replaced by flags + YAML config.
- **`--open`** (auto-launch Wireshark after capture) — intentionally
  skipped per an explicit "no GUI" requirement during development.
- **MTU-mismatch, SYN-flood, and IP-fragmentation detectors** — Explain
  Engine has entries for `syn_flood` and `fragmentation`, but there's no
  pcap-side detection logic wired up for these patterns yet (unlike
  retransmission/duplicate-ack/out-of-order/zero-window/reset/RTT/DNS,
  which are all detected automatically).
- **ICMP error checking** — not implemented.
- **Fixed-size single-file capture stop** (UC-03 in the original spec,
  "stop after N GB") — only the ring-buffer size limit (`--ring-size`)
  exists; there's no non-ring "stop this one file at N GB" flag.
- **Separate bundle files** (`routes.json`, `dns.json`, `iptables.json`,
  `conntrack.json` individually, per the original UC-07) — everything is
  combined into one `metadata.json` instead. Functionally equivalent,
  structurally different from the spec.
- **`pktdiag anomalies`** and **`pktdiag export`** as standalone command
  names — the functionality exists (anomalies are listed in every
  report/`analyze`/`diagnose`; export-to-format is `report --format`), just
  not under those exact command names.
- **Cross-platform support** — `internal/sysinfo` reads `/proc` and
  `/sys` directly; this is Linux-only by design (the original spec is
  Linux-oriented — `iptables`/`nft`/`conntrack`/`sysctl` are Linux
  concepts).

## Troubleshooting

**`tcpdump: <file>: Permission denied` during ring-buffer capture.**
Fixed as of the ring-buffer-analysis change — pktdiag now passes `-Z root`
to `tcpdump` when running as root, which prevents it from dropping
privileges before creating rotated ring files. If you're *not* running as
root and hit this, the unprivileged capture user (often `tcpdump` on
Debian/Ubuntu) needs write access to the output directory.

**`doctor` reports ✘ for `tcpdump`/`tshark`.** Install them (see
[Installation](#installation)). `dumpcap`/`capinfos`/`zstd`/`wkhtmltopdf`
missing only shows as ⚠ (optional) and doesn't block capture, except
`zstd` is needed for the final archive step (skippable with `--no-archive`).

**`report --format pdf` fails with "wkhtmltopdf не найден".** Install the
`wkhtmltopdf` package; PDF export shells out to it.

**Ring-buffer analysis says "no numbered files found".** This can happen
if the ring never rotated (traffic stayed below `--ring-size` during the
whole capture) — check for `<output>/capture.pcapng` without a numeric
suffix and analyze that directly with `pktdiag report`.

## License

See [LICENSE](LICENSE).
