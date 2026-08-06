// Package tui показывает отчёт pktdiag в интерактивном терминальном
// интерфейсе на Bubble Tea: вкладки Overview/TCP/DNS/Anomalies,
// переключение стрелками или цифрами, выход по q.
//
// Интерактивность этого пакета невозможно проверить автоматически: ни
// локальная песочница, ни раннер GitHub Actions не предоставляют
// псевдотерминал для настоящего запуска Bubble Tea program.Run(). CI
// подтверждает только то, что пакет собирается (go build) и что View()
// для каждой вкладки не паникует на реальных данных отчёта (см.
// tui_test.go). Саму интерактивность проверяет человек вручную.
package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"pktdiag/internal/report"
)

type tab int

const (
	tabOverview tab = iota
	tabTCP
	tabDNS
	tabAnomalies
)

var tabNames = []string{"Overview", "TCP", "DNS", "Anomalies"}

// Model хранит состояние интерактивного просмотра одного отчёта.
type Model struct {
	rep    report.Report
	active tab
}

// New создаёт модель для отчёта rep, начиная со вкладки Overview.
func New(rep report.Report) Model {
	return Model{rep: rep, active: tabOverview}
}

// Init не запускает фоновых команд: весь View строится из уже готового
// отчёта, дополнительно ничего загружать не нужно.
func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	switch keyMsg.String() {
	case "q", "ctrl+c", "esc":
		return m, tea.Quit
	case "right", "l", "tab":
		m.active = (m.active + 1) % tab(len(tabNames))
	case "left", "h", "shift+tab":
		m.active = (m.active - 1 + tab(len(tabNames))) % tab(len(tabNames))
	case "1":
		m.active = tabOverview
	case "2":
		m.active = tabTCP
	case "3":
		m.active = tabDNS
	case "4":
		m.active = tabAnomalies
	}
	return m, nil
}

func (m Model) View() string {
	var b strings.Builder

	for i, name := range tabNames {
		if tab(i) == m.active {
			fmt.Fprintf(&b, "[%s] ", name)
		} else {
			fmt.Fprintf(&b, " %s  ", name)
		}
	}
	b.WriteString("\n\n")

	switch m.active {
	case tabOverview:
		b.WriteString(m.overviewView())
	case tabTCP:
		b.WriteString(m.tcpView())
	case tabDNS:
		b.WriteString(m.dnsView())
	case tabAnomalies:
		b.WriteString(m.anomaliesView())
	}

	b.WriteString("\n\n← → или 1-4 переключить вкладку, q выход\n")
	return b.String()
}

func (m Model) overviewView() string {
	r := m.rep
	var b strings.Builder
	fmt.Fprintf(&b, "Источник:      %s\n", r.Meta.Source)
	fmt.Fprintf(&b, "Пакеты:        %d\n", r.Summary.Packets)
	fmt.Fprintf(&b, "Длительность:  %.1fs\n", r.Summary.DurationSec)
	fmt.Fprintf(&b, "Avg PPS:       %.0f\n", r.Summary.AvgPPS)
	fmt.Fprintf(&b, "\nHealth Score:  %d/100\n", r.Health.Total)
	for _, comp := range []string{"network", "tcp", "dns"} {
		if v, ok := r.Health.Components[comp]; ok {
			fmt.Fprintf(&b, "  %-8s %d\n", comp, v)
		}
	}
	fmt.Fprintf(&b, "\nПротоколы: TCP %d · UDP %d · ICMP %d · DNS %d · TLS %d · HTTP %d\n",
		r.Protocols.TCP, r.Protocols.UDP, r.Protocols.ICMP, r.Protocols.DNS, r.Protocols.TLS, r.Protocols.HTTP)
	return b.String()
}

func (m Model) tcpView() string {
	r := m.rep
	var b strings.Builder
	fmt.Fprintf(&b, "Retransmission:  %d (%.1f%%)\n", r.TCP.Retransmissions, r.TCP.RetransmissionPct)
	fmt.Fprintf(&b, "Duplicate ACK:   %d\n", r.TCP.DuplicateAcks)
	fmt.Fprintf(&b, "Out of Order:    %d\n", r.TCP.OutOfOrder)
	fmt.Fprintf(&b, "Zero Window:     %d\n", r.TCP.ZeroWindow)
	fmt.Fprintf(&b, "Reset:           %d\n", r.TCP.Resets)
	if r.RTT.Samples > 0 {
		fmt.Fprintf(&b, "\nRTT avg/min/max: %.1f / %.1f / %.1f мс (%d замеров)\n",
			r.RTT.AvgMs, r.RTT.MinMs, r.RTT.MaxMs, r.RTT.Samples)
	}
	fmt.Fprintf(&b, "\nFragmented:      %d\n", r.Deep.Fragmented)
	fmt.Fprintf(&b, "SYN без ответа:  %d/%d\n", r.Deep.SynOnly-r.Deep.SynAck, r.Deep.SynOnly)
	fmt.Fprintf(&b, "ICMP errors:     %d\n", r.Deep.ICMPErrors)
	return b.String()
}

func (m Model) dnsView() string {
	r := m.rep
	var b strings.Builder
	fmt.Fprintf(&b, "Запросы/Ответы:      %d/%d\n", r.DNS.Queries, r.DNS.Responses)
	fmt.Fprintf(&b, "Средний ответ:       %.1f мс\n", r.DNS.AvgResponseMs)
	fmt.Fprintf(&b, "Медленные (>200мс):  %d\n", r.DNS.SlowResponses)
	fmt.Fprintf(&b, "Вероятные таймауты:  %d\n", r.DNS.LikelyTimeouts)
	return b.String()
}

func (m Model) anomaliesView() string {
	r := m.rep
	if len(r.Anomalies) == 0 {
		return "Аномалий не обнаружено.\n"
	}
	var b strings.Builder
	for _, a := range r.Anomalies {
		mark := "⚠"
		if a.Severity == "critical" {
			mark = "✘"
		}
		fmt.Fprintf(&b, "%s %-22s %-14s %s\n", mark, a.Title, a.Value, a.Message)
	}
	return b.String()
}

// Run запускает интерактивную программу Bubble Tea на текущем терминале
// и блокируется до выхода пользователя (q/ctrl+c/esc).
func Run(rep report.Report) error {
	p := tea.NewProgram(New(rep))
	_, err := p.Run()
	return err
}
