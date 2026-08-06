# Explain Engine reference

🇷🇺 [Русская версия](EXPLAIN.ru.md)

`pktdiag explain <term>` (or `--explain` on `analyze` and `diagnose`)
looks up one of these terms. Aliases appear in parentheses.

| Term | Covers |
|---|---|
| `retransmission` (`tcp.retransmission`) | TCP segments resent because no ACK arrived in time |
| `duplicate_ack` | Receiver acknowledging the same byte twice, usually a missing segment |
| `out_of_order` | Packets arriving out of send order |
| `zero_window` | Receiver buffer full, sender told to pause |
| `rst` (`tcp.reset`) | Connection reset instead of a clean FIN close |
| `rtt` | Round-trip time and what a jump in it usually means |
| `dns_timeout` | DNS query sent, no response received |
| `dns_slow` | DNS response arrived slowly |
| `syn_flood` | Large volume of unanswered SYNs, a DoS pattern or unreachable service |
| `fragmentation` | IP packets split because they exceed path MTU |
| `packets_dropped` | Kernel dropped packets during capture, buffer or disk too slow |
| `bandwidth` (`throughput`) | Average data rate over the capture |
| `pps` (`packets per second`) | Average packet rate over the capture |
| `icmp_errors` (`icmp.errors`) | ICMP error messages, not regular ping traffic |
| `mtu_mismatch` (`mtu.mismatch`) | Active interfaces on one host report different MTU |

Each entry has good, warning, and critical thresholds, a plain
description, typical causes, and recommendations. The source lives in
[`internal/explainx/data/explain.json`](../internal/explainx/data/explain.json).
Add a term by adding a new JSON object to that file.
