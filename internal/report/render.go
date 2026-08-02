package report

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strings"
)

//go:embed templates/report.html.tmpl
var templatesFS embed.FS

var htmlTmpl = template.Must(template.ParseFS(templatesFS, "templates/report.html.tmpl"))

// WriteJSON сохраняет отчёт в формате JSON.
func WriteJSON(r Report, path string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}
	return os.WriteFile(path, b, 0o644)
}

// WriteHTML рендерит отчёт в HTML через встроенный шаблон.
func WriteHTML(r Report, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	if err := htmlTmpl.Execute(f, r); err != nil {
		return fmt.Errorf("render html: %w", err)
	}
	return nil
}

// WriteMarkdown рендерит компактный markdown-отчёт.
func WriteMarkdown(r Report, path string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# pktdiag — отчёт\n\n")
	fmt.Fprintf(&b, "- Источник: `%s`\n", r.Meta.Source)
	fmt.Fprintf(&b, "- Сформирован: %s\n", r.Meta.GeneratedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "- Health Score: **%d/100**\n\n", r.Health.Total)

	fmt.Fprintf(&b, "## Сводка\n\n")
	fmt.Fprintf(&b, "| Метрика | Значение |\n|---|---|\n")
	fmt.Fprintf(&b, "| Пакеты | %d |\n", r.Summary.Packets)
	fmt.Fprintf(&b, "| Длительность | %.1fs |\n", r.Summary.DurationSec)
	fmt.Fprintf(&b, "| Avg PPS | %.0f |\n", r.Summary.AvgPPS)
	if r.Capture != nil {
		fmt.Fprintf(&b, "| Dropped | %d |\n", r.Capture.PacketsDropped)
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "## Протоколы\n\n")
	fmt.Fprintf(&b, "TCP: %d · UDP: %d · ICMP: %d · DNS: %d · TLS: %d · HTTP: %d\n\n",
		r.Protocols.TCP, r.Protocols.UDP, r.Protocols.ICMP, r.Protocols.DNS, r.Protocols.TLS, r.Protocols.HTTP)

	fmt.Fprintf(&b, "## TCP\n\n")
	fmt.Fprintf(&b, "- Retransmission: %d (%.1f%%)\n", r.TCP.Retransmissions, r.TCP.RetransmissionPct)
	fmt.Fprintf(&b, "- Duplicate ACK: %d\n", r.TCP.DuplicateAcks)
	fmt.Fprintf(&b, "- Out of Order: %d\n", r.TCP.OutOfOrder)
	fmt.Fprintf(&b, "- Zero Window: %d\n", r.TCP.ZeroWindow)
	fmt.Fprintf(&b, "- Reset: %d\n\n", r.TCP.Resets)

	fmt.Fprintf(&b, "## DNS\n\n")
	fmt.Fprintf(&b, "- Запросы/Ответы: %d/%d\n", r.DNS.Queries, r.DNS.Responses)
	fmt.Fprintf(&b, "- Средний ответ: %.1f мс\n", r.DNS.AvgResponseMs)
	fmt.Fprintf(&b, "- Медленные (>200мс): %d\n", r.DNS.SlowResponses)
	fmt.Fprintf(&b, "- Вероятные таймауты: %d\n\n", r.DNS.LikelyTimeouts)

	fmt.Fprintf(&b, "## Аномалии\n\n")
	if len(r.Anomalies) == 0 {
		b.WriteString("Аномалий не обнаружено.\n")
	} else {
		for _, a := range r.Anomalies {
			fmt.Fprintf(&b, "- **[%s] %s** — %s: %s\n", strings.ToUpper(a.Severity), a.Title, a.Value, a.Message)
		}
	}

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// TerminalSummary формирует человекочитаемую сводку для вывода в консоль
// (аналог TUI-вкладки Overview из ТЗ, но без интерактивности).
func TerminalSummary(r Report) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Report\n")
	fmt.Fprintf(&b, "  Источник:            %s\n", r.Meta.Source)
	fmt.Fprintf(&b, "  Пакеты:              %d\n", r.Summary.Packets)
	fmt.Fprintf(&b, "  Длительность:        %.1fs\n", r.Summary.DurationSec)
	fmt.Fprintf(&b, "  Avg PPS:             %.0f\n", r.Summary.AvgPPS)
	if r.Capture != nil {
		fmt.Fprintf(&b, "  Интерфейс:           %s\n", r.Capture.Interface)
		if r.Capture.Filter != "" {
			fmt.Fprintf(&b, "  Фильтр:              %s\n", r.Capture.Filter)
		}
		fmt.Fprintf(&b, "  Dropped:             %d\n", r.Capture.PacketsDropped)
	}
	fmt.Fprintf(&b, "\nПротоколы\n")
	fmt.Fprintf(&b, "  TCP %d · UDP %d · ICMP %d · DNS %d · TLS %d · HTTP %d\n",
		r.Protocols.TCP, r.Protocols.UDP, r.Protocols.ICMP, r.Protocols.DNS, r.Protocols.TLS, r.Protocols.HTTP)

	fmt.Fprintf(&b, "\nNetwork Score: %d/100\n", r.Health.Total)
	for _, comp := range []string{"network", "tcp", "dns"} {
		if v, ok := r.Health.Components[comp]; ok {
			mark := "✓"
			if v < 100 {
				mark = "⚠"
			}
			fmt.Fprintf(&b, "  %s %-8s %d\n", mark, comp, v)
		}
	}

	fmt.Fprintf(&b, "\nАномалии\n")
	if len(r.Anomalies) == 0 {
		fmt.Fprintf(&b, "  нет\n")
	} else {
		for _, a := range r.Anomalies {
			sym := "⚠"
			if a.Severity == "critical" {
				sym = "✘"
			}
			fmt.Fprintf(&b, "  %s %-22s %-10s %s\n", sym, a.Title, a.Value, a.Message)
		}
	}
	fmt.Fprintf(&b, "\nПодробнее: pktdiag explain <термин>, например `pktdiag explain retransmission`\n")

	return b.String()
}
