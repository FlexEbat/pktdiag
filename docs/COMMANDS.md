# Command reference

🇷🇺 [Русская версия](COMMANDS.ru.md)

Every source argument for `report`, `analyze`, `diagnose`, `timeline`,
`inspect`, `compare`, and `health` accepts one of three forms:

- a direct path to a `.pcap`/`.pcapng` file
- a directory (pktdiag uses the first `*.pcap`/`*.pcapng` file it finds inside)
- a `.tar.zst` bundle produced by `pktdiag capture` (pktdiag extracts it to a
  temp directory automatically, including `metadata.json` if present)

## pktdiag doctor

Checks the environment: presence of `tcpdump`, `dumpcap`, `tshark`,
`capinfos`, `mergecap`, `zstd`, `wkhtmltopdf`, `iptables`, `nft`,
`conntrack`; current permissions; free disk space; available network
interfaces. A missing required tool marks the check ✘ and blocks capture.
A missing optional tool marks ⚠ and does not block capture.

```
pktdiag doctor [flags]

  --install    offer to install missing packages, or install them
               immediately with --yes
  --yes        skip the confirmation prompt (use with --install)
```

```bash
pktdiag doctor
pktdiag doctor --install
sudo pktdiag doctor --install --yes
```

Automatic installation supports apt (Debian, Ubuntu) and requires root.
On dnf, yum, pacman, apk, or brew, `doctor` prints the equivalent manual
install command instead of running it. If `apt-get update` fails because
an unrelated third-party repository is unreachable, pktdiag logs a
warning and still runs `apt-get install`, since the packages pktdiag
needs usually live in the main distro repositories.

## pktdiag capture

Runs the full pipeline: capture, metadata collection, analysis, report,
archive.

```
pktdiag capture [flags]

  --iface STRING       network interface (default: auto-picked, skips lo)
  --filter STRING      BPF filter, for example "tcp port 443"
  --duration STRING    for example "30s", "5m". "0" captures until Ctrl+C (default 30s)
  --output DIR         results directory (default ./pktdiag-capture-<timestamp>)
  --format LIST        comma-separated report formats: html,json,md,pdf (default html,json)
  --no-archive         skip building the final tar.zst
  --ring N             enable ring buffer with N files (0 disables it)
  --ring-size MB       size per ring file in MB (default 100)
  --snaplen N          tcpdump snapshot length (0 means unlimited, -s0)
  --max-size SIZE      stop a single file at this size, for example "500MB", "2GB" (mutually exclusive with --ring)
  --open               open the capture in Wireshark when it finishes (needs a GUI environment)
  --interactive        walk through interface, filter, and duration selection step by step, ignoring --iface/--filter/--duration
  --force              proceed even if doctor found blocking (✘) issues
  --config PATH         YAML config file (default ./pktdiag.yaml if present)
```

Output layout inside `--output`:

```
capture.pcapng            raw capture
metadata.json             host snapshot: uname, cpu/ram, interfaces, routes,
                          dns, iptables/nftables rules, conntrack sample, sysctl
report.json/html/md/pdf   one file per requested --format
```

pktdiag also writes `<output-dir>.tar.zst` next to the output directory,
unless you pass `--no-archive`.

With `--ring N`, pktdiag locates the resulting ring files
(`capture.pcapng0`, `capture.pcapng1`, and so on) after capture, merges
them with `mergecap` into `capture.merged.pcapng`, and analyzes the merged
file. Ring-buffer captures get full analysis, not just the last file.

When it runs as root, pktdiag adds `-Z root` to the `tcpdump` invocation.
Without this flag, `tcpdump` on Debian and Ubuntu drops privileges to the
`tcpdump` user right after opening the interface. That unprivileged user
cannot create new ring files in a directory owned by root, and capture
fails partway through with `Permission denied`.

```bash
pktdiag capture --iface eth0 --duration 5m
pktdiag capture --iface eth0 --filter "udp port 53" --duration 0
pktdiag capture --ring 5 --ring-size 50 --duration 10m
pktdiag capture --config prod.yaml --duration 10s
pktdiag capture --interactive
pktdiag capture --max-size 500MB
pktdiag capture --open
```

`--interactive` prompts for the interface, filter, and duration one at a
time instead of reading `--iface`, `--filter`, and `--duration`. Every
other flag (`--output`, `--format`, `--ring`, and so on) still applies
normally alongside it.

`--max-size` stops a single output file once it reaches the given size,
without rotating into multiple files. It is mutually exclusive with
`--ring`, which has its own per-file size limit through `--ring-size`.
Sizes use decimal SI units (1MB = 1,000,000 bytes), matching tcpdump's
own `-C` flag.

`--open` launches `wireshark` on the finished capture and returns
immediately, without waiting for the window to close. It needs
`wireshark` installed and a GUI environment (`$DISPLAY` or
`$WAYLAND_DISPLAY` set); pktdiag warns but does not fail the capture if
either is missing.

## pktdiag report

Builds a report from an existing capture without recapturing.

```
pktdiag report <source> [flags]

  --format LIST    html,json,md,pdf (default html,json)
  --output DIR     where to write the report (default: next to the source)
```

```bash
pktdiag report ./capture.pcapng --format html,pdf
pktdiag report ./bundle.tar.zst --output ./out
```

## pktdiag analyze

Prints a plain-text overview to the terminal.

```
pktdiag analyze <source> [flags]

  --explain    print the full Explain Engine entry for every detected anomaly
  --save LIST   additionally write report files (html,json,md,pdf)
  --output DIR   where to write --save output (default: next to source)
```

```bash
pktdiag analyze ./bundle.tar.zst --explain
pktdiag analyze ./capture.pcapng --save json --output ./out
```

## pktdiag explain

Looks up a term in the Explain Engine and prints its norm, warning, and
critical thresholds, a plain description, likely causes, and
recommendations. Running it without an argument lists every known term.
See [EXPLAIN.md](EXPLAIN.md) for the full list.

```bash
pktdiag explain retransmission
pktdiag explain dns_slow
pktdiag explain
```

## pktdiag diagnose

Groups every detected anomaly into a category (packet loss, latency,
receive buffer, connection issues, DNS, fragmentation), picks the
dominant category, and reports a probable cause with a confidence score,
plus causes and recommendations pulled from the Explain Engine. The
confidence score is a fixed heuristic, not a model: it sums the severity
weight of anomalies in the winning category and caps the result at 96%.

```bash
pktdiag diagnose ./bundle.tar.zst
```

## pktdiag timeline

Lists TCP and DNS events in chronological order: retransmission,
duplicate ACK, out-of-order, zero window, reset, DNS error response.
Each line shows a timestamp and `src:port -> dst:port`.

```bash
pktdiag timeline ./capture.pcapng
```

## pktdiag inspect

Prints a checklist: MSS and Window Scale presence in SYN packets,
retransmission count, zero window count, keepalive count for TCP; slow
responses for DNS; alert messages for TLS.

```bash
pktdiag inspect ./capture.pcapng
```

## pktdiag compare

Builds reports for two captures and prints a diff table: RTT, average DNS
response time, retransmission count and percentage, zero window, resets,
dropped packets, average PPS, Health Score.

```bash
pktdiag compare ./before.tar.zst ./after.tar.zst
```

## pktdiag health

Prints only the Health Score and its component breakdown (network, tcp,
dns), for quick checks or scripting.

```bash
pktdiag health ./capture.pcapng
```

## pktdiag tui

Opens an interactive terminal viewer for one report: tabs for Overview,
TCP, DNS, and Anomalies. Switch tabs with the arrow keys, Tab, or number
keys 1 through 4. Quit with `q`, `Esc`, or `Ctrl+C`.

```bash
pktdiag tui ./capture.pcapng
```

## Report formats & schema

Every `report.json` follows this shape (trimmed for brevity, see
[`internal/report/model.go`](../internal/report/model.go) for the exact
Go structs):

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

`report.html` renders the same data as a self-contained, dark-themed
static page. `report.md` is a compact summary for pasting into a ticket.
`report.pdf` converts the HTML version through `wkhtmltopdf`.
