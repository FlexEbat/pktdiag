package analyze

import (
	"fmt"

	"pktdiag/internal/report"
)

// AddSystemChecks добавляет аномалии, которые видны только по
// metadata.json (System), а не по самому pcap: сейчас это расхождение
// MTU между активными интерфейсами хоста. Вызывающий код зовёт функцию
// после установки rep.System; она пересчитывает Health Score.
func AddSystemChecks(rep *report.Report) {
	if rep.System == nil {
		return
	}

	mtus := map[int]bool{}
	var names []string
	for _, iface := range rep.System.Interfaces {
		if iface.Name == "lo" || iface.State != "up" || iface.MTU == 0 {
			continue
		}
		mtus[iface.MTU] = true
		names = append(names, fmt.Sprintf("%s=%d", iface.Name, iface.MTU))
	}

	if len(mtus) > 1 {
		rep.Anomalies = append(rep.Anomalies, report.Anomaly{
			ID:       "mtu_mismatch",
			Severity: "warning",
			Title:    "MTU Mismatch",
			Value:    fmt.Sprintf("%v", names),
			Message:  "Активные интерфейсы хоста сообщают разный MTU. Источник фрагментации или проблем PMTUD",
		})
	}

	rep.Health = healthScore(*rep)
}
