package analyze

import "fmt"

// InspectItem хранит одну строку чек-листа.
type InspectItem struct {
	Group  string `json:"group"` // TCP | DNS | TLS
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// InspectFromReport строит чек-лист, переиспользуя уже посчитанную статистику
// (report.Report) и добавляя точечные проверки, которых там нет
// (MSS/Window Scale в SYN, TLS alerts, keepalive), см. UC-20 в ТЗ.
func InspectFromReport(pcapPath string, tcpTotal, dnsTotal, tlsTotal int,
	retransmissions, zeroWindow int) ([]InspectItem, error) {

	var items []InspectItem

	if tcpTotal > 0 {
		synTotal, err := countFilter(pcapPath, "tcp.flags.syn==1")
		if err != nil {
			return nil, err
		}
		mssCount, err := countFilter(pcapPath, "tcp.flags.syn==1 && tcp.options.mss")
		if err != nil {
			return nil, err
		}
		wscaleCount, err := countFilter(pcapPath, "tcp.flags.syn==1 && tcp.options.wscale")
		if err != nil {
			return nil, err
		}
		keepalive, err := countFilter(pcapPath, "tcp.analysis.keep_alive")
		if err != nil {
			return nil, err
		}

		items = append(items,
			checklistItem("TCP", "MSS в SYN", synTotal == 0 || mssCount == synTotal,
				fmt.Sprintf("%d/%d SYN с MSS", mssCount, synTotal)),
			checklistItem("TCP", "Window Scale", synTotal == 0 || wscaleCount == synTotal,
				fmt.Sprintf("%d/%d SYN с Window Scale", wscaleCount, synTotal)),
			checklistItem("TCP", "Retransmission", retransmissions == 0,
				fmt.Sprintf("%d ретрансмиссий", retransmissions)),
			checklistItem("TCP", "Zero Window", zeroWindow == 0,
				fmt.Sprintf("%d раз", zeroWindow)),
			checklistItem("TCP", "Keepalive", true, // информационно, не является проблемой само по себе
				fmt.Sprintf("%d keepalive-пакетов", keepalive)),
		)
	}

	if dnsTotal > 0 {
		slow, err := countFilter(pcapPath, "dns.time > 0.2")
		if err != nil {
			return nil, err
		}
		items = append(items, checklistItem("DNS", "Slow Response", slow == 0,
			fmt.Sprintf("%d ответов медленнее 200мс", slow)))
	} else {
		items = append(items, checklistItem("DNS", "трафик отсутствует", true, ""))
	}

	if tlsTotal > 0 {
		alerts, err := countFilter(pcapPath, "tls.alert_message")
		if err != nil {
			return nil, err
		}
		items = append(items, checklistItem("TLS", "Alerts", alerts == 0,
			fmt.Sprintf("%d TLS alert-сообщений", alerts)))
	} else {
		items = append(items, checklistItem("TLS", "трафик отсутствует", true, ""))
	}

	return items, nil
}

func checklistItem(group, name string, ok bool, detail string) InspectItem {
	return InspectItem{Group: group, Name: name, OK: ok, Detail: detail}
}
