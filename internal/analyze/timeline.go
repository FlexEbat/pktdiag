package analyze

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TimelineEvent — одно событие на хронологической ленте.
type TimelineEvent struct {
	Time   time.Time `json:"time"`
	Label  string    `json:"label"`
	Detail string    `json:"detail,omitempty"`
}

type timelineSource struct {
	filter string
	label  string
}

var timelineSources = []timelineSource{
	{"tcp.analysis.retransmission", "TCP Retransmission"},
	{"tcp.analysis.duplicate_ack", "TCP Duplicate ACK"},
	{"tcp.analysis.out_of_order", "TCP Out of Order"},
	{"tcp.analysis.zero_window", "TCP Zero Window"},
	{"tcp.flags.reset==1", "TCP Reset"},
	{"dns.flags.rcode!=0", "DNS Error Response"},
}

// BuildTimeline извлекает из pcap хронологический список событий,
// интересных для диагностики (см. UC-14 в ТЗ).
func BuildTimeline(pcapPath string) ([]TimelineEvent, error) {
	var events []TimelineEvent

	for _, src := range timelineSources {
		rows, err := timelineFields(pcapPath, src.filter)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			events = append(events, TimelineEvent{
				Time:   row.t,
				Label:  src.label,
				Detail: row.detail,
			})
		}
	}

	sortEventsByTime(events)
	return events, nil
}

type timelineRow struct {
	t      time.Time
	detail string
}

func timelineFields(pcapPath, filter string) ([]timelineRow, error) {
	out, err := runTsharkFields(pcapPath, filter,
		"frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport")
	if err != nil {
		return nil, err
	}
	var rows []timelineRow
	for _, fields := range out {
		if len(fields) < 1 || fields[0] == "" {
			continue
		}
		sec, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			continue
		}
		t := time.Unix(0, int64(sec*1e9))
		detail := ""
		if len(fields) >= 5 && fields[1] != "" {
			detail = fmt.Sprintf("%s:%s -> %s:%s", fields[1], fields[3], fields[2], fields[4])
		}
		rows = append(rows, timelineRow{t: t, detail: detail})
	}
	return rows, nil
}

func sortEventsByTime(events []TimelineEvent) {
	for i := 1; i < len(events); i++ {
		for j := i; j > 0 && events[j].Time.Before(events[j-1].Time); j-- {
			events[j], events[j-1] = events[j-1], events[j]
		}
	}
}

// FormatTimeline форматирует события для вывода в терминал.
func FormatTimeline(events []TimelineEvent) string {
	if len(events) == 0 {
		return "События не найдены — заметных TCP/DNS-аномалий в захвате нет.\n"
	}
	var b strings.Builder
	for _, e := range events {
		fmt.Fprintf(&b, "%s  %-24s %s\n", e.Time.Format("15:04:05.000"), e.Label, e.Detail)
	}
	return b.String()
}
