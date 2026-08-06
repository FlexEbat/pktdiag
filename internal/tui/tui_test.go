package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"pktdiag/internal/report"
)

// keyMsg строит tea.KeyMsg так, чтобы msg.String() вернул именно s: для
// именованных клавиш (right/left/esc/tab) через Type, для одиночных
// символов (цифры, буквы) через Runes с типом KeyRunes.
func keyMsg(s string) tea.KeyMsg {
	switch s {
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

// TestViewDoesNotPanic прогоняет View() по каждой вкладке на двух формах
// отчёта: с данными и полностью пустой (все счётчики нулевые, карты nil).
// Не проверяет интерактивность Bubble Tea (это невозможно без псевдотерминала,
// см. пакетный комментарий в tui.go), но ловит панику на nil-картах и
// делении на дефолтные значения, которую иначе увидели бы только руками.
func TestViewDoesNotPanic(t *testing.T) {
	reports := map[string]report.Report{
		"с данными": {
			Meta:      report.Meta{Source: "test.pcapng"},
			Summary:   report.Summary{Packets: 100, DurationSec: 10, AvgPPS: 10},
			Protocols: report.Protocols{TCP: 60, UDP: 20, ICMP: 5, DNS: 10, TLS: 30, HTTP: 0},
			TCP:       report.TCPStats{Retransmissions: 5, RetransmissionPct: 8.3, DuplicateAcks: 2, OutOfOrder: 1, ZeroWindow: 1, Resets: 3},
			RTT:       report.RTTStats{Samples: 20, AvgMs: 12.5, MinMs: 1, MaxMs: 40},
			Deep:      report.DeepStats{Fragmented: 2, SynOnly: 3, SynAck: 2, ICMPErrors: 1},
			DNS:       report.DNSStats{Queries: 10, Responses: 9, AvgResponseMs: 45, SlowResponses: 1, LikelyTimeouts: 1},
			Anomalies: []report.Anomaly{
				{ID: "retransmission", Severity: "warning", Title: "TCP Retransmission", Value: "8.3%", Message: "тест"},
				{ID: "rst", Severity: "critical", Title: "TCP Reset", Value: "3", Message: "тест"},
			},
			Health: report.HealthScore{Total: 72, Components: map[string]int{"network": 80, "tcp": 60, "dns": 90}},
		},
		"пустой": {},
	}

	for name, rep := range reports {
		m := New(rep)
		for tabIdx := 0; tabIdx < len(tabNames); tabIdx++ {
			m.active = tab(tabIdx)
			view := m.View()
			if !strings.Contains(view, tabNames[tabIdx]) {
				t.Errorf("[%s] вкладка %s: View() не содержит имени вкладки", name, tabNames[tabIdx])
			}
			if view == "" {
				t.Errorf("[%s] вкладка %s: View() вернул пустую строку", name, tabNames[tabIdx])
			}
		}
	}
}

// TestUpdateNavigation проверяет переключение вкладок клавишами без
// запуска настоящей Bubble Tea program. Update() чистая функция,
// её можно вызвать напрямую с синтетическими tea.KeyMsg.
func TestUpdateNavigation(t *testing.T) {
	m := New(report.Report{})
	if m.active != tabOverview {
		t.Fatalf("начальная вкладка = %v, ожидалась tabOverview", m.active)
	}

	next, _ := m.Update(keyMsg("right"))
	m = next.(Model)
	if m.active != tabTCP {
		t.Fatalf("после 'right' active = %v, ожидалась tabTCP", m.active)
	}

	next, _ = m.Update(keyMsg("3"))
	m = next.(Model)
	if m.active != tabDNS {
		t.Fatalf("после '3' active = %v, ожидалась tabDNS", m.active)
	}

	next, _ = m.Update(keyMsg("left"))
	m = next.(Model)
	if m.active != tabTCP {
		t.Fatalf("после 'left' от tabDNS active = %v, ожидалась tabTCP", m.active)
	}
}
