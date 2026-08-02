package analyze

import (
	"fmt"
	"time"

	"pktdiag/internal/report"
)

// Build анализирует pcap-файл через tshark/capinfos и возвращает
// заполненный report.Report (без блока System — его добавляет вызывающий код).
func Build(pcapPath string, capture *report.CaptureInfo) (report.Report, error) {
	var rep report.Report
	rep.Meta = report.Meta{
		GeneratedAt:    time.Now(),
		PktdiagVersion: "0.1.0-mvp",
		Source:         pcapPath,
	}
	rep.Capture = capture

	if err := requireTools(); err != nil {
		return rep, err
	}

	ci, err := runCapinfos(pcapPath)
	if err != nil {
		return rep, err
	}

	proto, err := countProtocols(pcapPath)
	if err != nil {
		return rep, err
	}
	rep.Protocols = proto

	tcp, err := countTCP(pcapPath, int64(proto.TCP))
	if err != nil {
		return rep, err
	}
	rep.TCP = tcp

	dns, err := countDNS(pcapPath, proto.DNS)
	if err != nil {
		return rep, err
	}
	rep.DNS = dns

	rep.Summary = report.Summary{
		Packets:     ci.Packets,
		DurationSec: ci.DurationSec,
	}
	if ci.DurationSec > 0 {
		rep.Summary.AvgPPS = float64(ci.Packets) / ci.DurationSec
	}

	rep.Anomalies = detectAnomalies(rep)
	rep.Health = healthScore(rep)

	return rep, nil
}

func countProtocols(pcapPath string) (report.Protocols, error) {
	var p report.Protocols
	var err error

	if p.TCP, err = countFilter(pcapPath, "tcp"); err != nil {
		return p, err
	}
	if p.UDP, err = countFilter(pcapPath, "udp"); err != nil {
		return p, err
	}
	if p.ICMP, err = countFilter(pcapPath, "icmp || icmpv6"); err != nil {
		return p, err
	}
	if p.DNS, err = countFilter(pcapPath, "dns"); err != nil {
		return p, err
	}
	if p.TLS, err = countFilter(pcapPath, "tls"); err != nil {
		return p, err
	}
	if p.HTTP, err = countFilter(pcapPath, "http"); err != nil {
		return p, err
	}
	return p, nil
}

func countTCP(pcapPath string, tcpTotal int64) (report.TCPStats, error) {
	var t report.TCPStats
	var err error

	if t.Retransmissions, err = countFilter(pcapPath, "tcp.analysis.retransmission"); err != nil {
		return t, err
	}
	if t.DuplicateAcks, err = countFilter(pcapPath, "tcp.analysis.duplicate_ack"); err != nil {
		return t, err
	}
	if t.ZeroWindow, err = countFilter(pcapPath, "tcp.analysis.zero_window"); err != nil {
		return t, err
	}
	if t.Resets, err = countFilter(pcapPath, "tcp.flags.reset==1"); err != nil {
		return t, err
	}
	if t.OutOfOrder, err = countFilter(pcapPath, "tcp.analysis.out_of_order"); err != nil {
		return t, err
	}
	t.RetransmissionPct = pct(int64(t.Retransmissions), tcpTotal)
	return t, nil
}

func countDNS(pcapPath string, dnsTotal int) (report.DNSStats, error) {
	var d report.DNSStats
	var err error

	if d.Queries, err = countFilter(pcapPath, "dns.flags.response==0"); err != nil {
		return d, err
	}
	if d.Responses, err = countFilter(pcapPath, "dns.flags.response==1"); err != nil {
		return d, err
	}
	times, err := fieldValues(pcapPath, "dns.flags.response==1", "dns.time")
	if err != nil {
		return d, err
	}
	d.AvgResponseMs = avg(times) * 1000
	for _, t := range times {
		if t*1000 > 200 {
			d.SlowResponses++
		}
	}
	if d.Queries > d.Responses {
		d.LikelyTimeouts = d.Queries - d.Responses
	}
	return d, nil
}

// detectAnomalies применяет пороги из Explain Engine (см. data/explain.json)
// и формирует список замечаний для отчёта/TUI.
func detectAnomalies(r report.Report) []report.Anomaly {
	var out []report.Anomaly

	// TCP retransmission: good <1%, warning 1-5%, critical >5%
	if r.Protocols.TCP > 0 {
		switch {
		case r.TCP.RetransmissionPct > 5:
			out = append(out, anomaly("retransmission", "critical", "TCP Retransmission",
				fmt.Sprintf("%.1f%%", r.TCP.RetransmissionPct),
				fmt.Sprintf("%d ретрансмиссий (%.1f%% от TCP-трафика) — выше нормы (<1%%)", r.TCP.Retransmissions, r.TCP.RetransmissionPct)))
		case r.TCP.RetransmissionPct >= 1:
			out = append(out, anomaly("retransmission", "warning", "TCP Retransmission",
				fmt.Sprintf("%.1f%%", r.TCP.RetransmissionPct),
				fmt.Sprintf("%d ретрансмиссий (%.1f%% от TCP-трафика)", r.TCP.Retransmissions, r.TCP.RetransmissionPct)))
		}
	}

	if r.TCP.DuplicateAcks > 0 {
		sev := "warning"
		if pct(int64(r.TCP.DuplicateAcks), int64(r.Protocols.TCP)) > 5 {
			sev = "critical"
		}
		out = append(out, anomaly("duplicate_ack", sev, "TCP Duplicate ACK",
			fmt.Sprintf("%d", r.TCP.DuplicateAcks),
			fmt.Sprintf("%d дубликатов ACK — получатель ждёт пропущенный сегмент", r.TCP.DuplicateAcks)))
	}

	if r.TCP.OutOfOrder > 0 {
		sev := "warning"
		if pct(int64(r.TCP.OutOfOrder), int64(r.Protocols.TCP)) > 5 {
			sev = "critical"
		}
		out = append(out, anomaly("out_of_order", sev, "TCP Out of Order",
			fmt.Sprintf("%d", r.TCP.OutOfOrder),
			fmt.Sprintf("%d пакетов пришли не по порядку", r.TCP.OutOfOrder)))
	}

	if r.TCP.ZeroWindow > 0 {
		out = append(out, anomaly("zero_window", "warning", "TCP Zero Window",
			fmt.Sprintf("%d", r.TCP.ZeroWindow),
			fmt.Sprintf("%d раз получатель сообщал о переполненном буфере", r.TCP.ZeroWindow)))
	}

	if r.TCP.Resets > 0 {
		sev := "warning"
		if pct(int64(r.TCP.Resets), int64(r.Protocols.TCP)) > 10 {
			sev = "critical"
		}
		out = append(out, anomaly("rst", sev, "TCP Reset",
			fmt.Sprintf("%d", r.TCP.Resets),
			fmt.Sprintf("%d RST-пакетов", r.TCP.Resets)))
	}

	if r.DNS.LikelyTimeouts > 0 {
		out = append(out, anomaly("dns_timeout", "warning", "DNS Timeout",
			fmt.Sprintf("%d", r.DNS.LikelyTimeouts),
			fmt.Sprintf("%d DNS-запросов остались без ответа в захвате", r.DNS.LikelyTimeouts)))
	}

	if r.DNS.AvgResponseMs > 200 {
		out = append(out, anomaly("dns_slow", "critical", "Медленный DNS",
			fmt.Sprintf("%.0f мс", r.DNS.AvgResponseMs),
			fmt.Sprintf("Средний ответ DNS %.0f мс — выше критического порога (200 мс)", r.DNS.AvgResponseMs)))
	} else if r.DNS.AvgResponseMs > 50 {
		out = append(out, anomaly("dns_slow", "warning", "Медленный DNS",
			fmt.Sprintf("%.0f мс", r.DNS.AvgResponseMs),
			fmt.Sprintf("Средний ответ DNS %.0f мс", r.DNS.AvgResponseMs)))
	}

	if r.Capture != nil && r.Capture.PacketsDropped > 0 {
		out = append(out, anomaly("packets_dropped", "warning", "Packets Dropped",
			fmt.Sprintf("%d", r.Capture.PacketsDropped),
			fmt.Sprintf("Ядро отбросило %d пакетов при захвате — данные могут быть неполными", r.Capture.PacketsDropped)))
	}

	return out
}

func anomaly(id, severity, title, value, message string) report.Anomaly {
	return report.Anomaly{ID: id, Severity: severity, Title: title, Value: value, Message: message}
}

// healthScore — эвристическая оценка (MVP): 100 минус штрафы за
// warning/critical аномалии, с раскладкой по компонентам.
func healthScore(r report.Report) report.HealthScore {
	total := 100
	components := map[string]int{"network": 100, "tcp": 100, "dns": 100}

	penalize := func(comp string, sev string) {
		delta := 3
		if sev == "critical" {
			delta = 10
		}
		total -= delta
		components[comp] -= delta
	}

	for _, a := range r.Anomalies {
		switch a.ID {
		case "retransmission", "duplicate_ack", "out_of_order":
			penalize("tcp", a.Severity)
		case "zero_window", "rst":
			penalize("network", a.Severity)
		case "dns_timeout", "dns_slow":
			penalize("dns", a.Severity)
		case "packets_dropped":
			penalize("network", a.Severity)
		}
	}

	clamp := func(v int) int {
		if v < 0 {
			return 0
		}
		if v > 100 {
			return 100
		}
		return v
	}
	total = clamp(total)
	for k, v := range components {
		components[k] = clamp(v)
	}

	return report.HealthScore{Total: total, Components: components}
}
