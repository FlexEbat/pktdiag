// Package report описывает структуру отчёта pktdiag и сериализует
// её в JSON, HTML и Markdown.
package report

import (
	"time"

	"pktdiag/internal/sysinfo"
)

// Meta хранит общую информацию об отчёте.
type Meta struct {
	GeneratedAt    time.Time `json:"generated_at"`
	PktdiagVersion string    `json:"pktdiag_version"`
	Source         string    `json:"source"`
}

// CaptureInfo хранит параметры и итоги захвата. Пусто, если отчёт
// построен по уже существующему pcap без сопровождающих метаданных.
type CaptureInfo struct {
	Interface         string    `json:"interface,omitempty"`
	Filter            string    `json:"filter,omitempty"`
	DurationRequested string    `json:"duration_requested,omitempty"`
	StartedAt         time.Time `json:"started_at,omitempty"`
	EndedAt           time.Time `json:"ended_at,omitempty"`
	PacketsReceived   int64     `json:"packets_received_by_filter"`
	PacketsDropped    int64     `json:"packets_dropped_by_kernel"`
}

// Summary хранит верхнеуровневые цифры по трафику.
type Summary struct {
	Packets     int64   `json:"packets"`
	DurationSec float64 `json:"duration_sec"`
	AvgPPS      float64 `json:"avg_pps"`
	AvgMbps     float64 `json:"avg_mbps"`
	Bytes       int64   `json:"bytes,omitempty"`
}

// Protocols хранит количество пакетов по основным протоколам.
type Protocols struct {
	TCP  int `json:"tcp"`
	UDP  int `json:"udp"`
	ICMP int `json:"icmp"`
	DNS  int `json:"dns"`
	TLS  int `json:"tls"`
	HTTP int `json:"http"`
}

// RTTStats хранит метрики задержки на основе TCP ACK RTT.
type RTTStats struct {
	Samples int     `json:"samples"`
	AvgMs   float64 `json:"avg_ms"`
	MinMs   float64 `json:"min_ms"`
	MaxMs   float64 `json:"max_ms"`
}

// DeepStats хранит метрики построчного разбора pcap через gopacket.
// tshark считает эти метрики только по display-filter, DeepStats
// заполняется прямым чтением IP/TCP/ICMP-заголовков.
type DeepStats struct {
	Fragmented int `json:"fragmented"`  // IPv4 с MF=1 или fragment offset != 0
	SynOnly    int `json:"syn_only"`    // TCP SYN без ACK
	SynAck     int `json:"syn_ack"`     // TCP SYN+ACK, ответ на попытку
	ICMPErrors int `json:"icmp_errors"` // ICMPv4 с кодом ошибки
}

// TCPStats хранит метрики качества TCP-потоков.
type TCPStats struct {
	Retransmissions   int     `json:"retransmissions"`
	RetransmissionPct float64 `json:"retransmission_pct"`
	DuplicateAcks     int     `json:"duplicate_acks"`
	ZeroWindow        int     `json:"zero_window"`
	Resets            int     `json:"resets"`
	OutOfOrder        int     `json:"out_of_order"`
}

// DNSStats хранит метрики качества DNS.
type DNSStats struct {
	Queries        int     `json:"queries"`
	Responses      int     `json:"responses"`
	AvgResponseMs  float64 `json:"avg_response_ms"`
	SlowResponses  int     `json:"slow_responses"`  // > 200ms
	LikelyTimeouts int     `json:"likely_timeouts"` // запросы без ответа
}

// Anomaly хранит одну обнаруженную аномалию.
type Anomaly struct {
	ID       string `json:"id"`       // совпадает с explainx.Entry.ID
	Severity string `json:"severity"` // ok | warning | critical
	Title    string `json:"title"`
	Value    string `json:"value"`
	Message  string `json:"message"`
}

// HealthScore хранит сводную оценку качества сети.
type HealthScore struct {
	Total      int            `json:"total"`
	Components map[string]int `json:"components"`
}

// Report хранит полный отчёт pktdiag.
type Report struct {
	Meta      Meta                `json:"meta"`
	Capture   *CaptureInfo        `json:"capture,omitempty"`
	Summary   Summary             `json:"summary"`
	Protocols Protocols           `json:"protocols"`
	TCP       TCPStats            `json:"tcp"`
	RTT       RTTStats            `json:"rtt"`
	Deep      DeepStats           `json:"deep"`
	DNS       DNSStats            `json:"dns"`
	Anomalies []Anomaly           `json:"anomalies"`
	Health    HealthScore         `json:"health_score"`
	System    *sysinfo.SystemInfo `json:"system,omitempty"`
}
