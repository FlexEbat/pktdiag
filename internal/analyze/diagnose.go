package analyze

import (
	"pktdiag/internal/explainx"
	"pktdiag/internal/report"
)

// Diagnosis хранит результат команды `pktdiag diagnose` (UC-19 из ТЗ).
type Diagnosis struct {
	ProbableCause   string   `json:"probable_cause"`
	Confidence      int      `json:"confidence"` // 0-100, эвристика
	Category        string   `json:"category"`   // packet_loss | latency | buffer | connectivity | dns | fragmentation | healthy
	Signals         []string `json:"signals"`    // какие аномалии легли в основу диагноза
	Causes          []string `json:"causes"`
	Recommendations []string `json:"recommendations"`
}

var categoryTitles = map[string]string{
	"packet_loss":   "Потери пакетов",
	"latency":       "Повышенная задержка (RTT)",
	"buffer":        "Переполнение приёмного буфера получателя",
	"connectivity":  "Проблемы установления/поддержания соединений",
	"dns":           "Проблемы DNS-резолвинга",
	"fragmentation": "Фрагментация IP-пакетов",
	"healthy":       "Существенных проблем не обнаружено",
}

func anomalyCategory(id string) string {
	switch id {
	case "retransmission", "duplicate_ack", "out_of_order", "packets_dropped":
		return "packet_loss"
	case "rtt":
		return "latency"
	case "zero_window":
		return "buffer"
	case "rst", "syn_flood":
		return "connectivity"
	case "dns_timeout", "dns_slow":
		return "dns"
	case "fragmentation":
		return "fragmentation"
	default:
		return ""
	}
}

// Diagnose группирует найденные аномалии по категориям, выбирает
// доминирующую и формирует вероятную причину с эвристической уверенностью.
// Это MVP-эвристика (не ML): вес критической аномалии выше warning,
// уверенность растёт с суммарным весом сигналов в категории.
func Diagnose(rep report.Report) Diagnosis {
	if len(rep.Anomalies) == 0 {
		return Diagnosis{
			ProbableCause: categoryTitles["healthy"],
			Confidence:    90,
			Category:      "healthy",
		}
	}

	scores := map[string]int{}
	signalsByCat := map[string][]string{}
	for _, a := range rep.Anomalies {
		cat := anomalyCategory(a.ID)
		if cat == "" {
			continue
		}
		weight := 3
		if a.Severity == "critical" {
			weight = 10
		}
		scores[cat] += weight
		signalsByCat[cat] = append(signalsByCat[cat], a.Title+" — "+a.Value)
	}

	if len(scores) == 0 {
		return Diagnosis{ProbableCause: categoryTitles["healthy"], Confidence: 80, Category: "healthy"}
	}

	// Выбираем категорию с наибольшим суммарным весом.
	topCat, topScore := "", -1
	for cat, sc := range scores {
		if sc > topScore {
			topCat, topScore = cat, sc
		}
	}

	confidence := 50 + topScore*4
	if confidence > 96 {
		confidence = 96
	}

	var causes, recs []string
	seenCause := map[string]bool{}
	seenRec := map[string]bool{}
	for _, a := range rep.Anomalies {
		if anomalyCategory(a.ID) != topCat {
			continue
		}
		entry, ok := explainx.Lookup(a.ID)
		if !ok {
			continue
		}
		for _, c := range entry.Causes {
			if !seenCause[c] {
				seenCause[c] = true
				causes = append(causes, c)
			}
		}
		for _, r := range entry.Recommendations {
			if !seenRec[r] {
				seenRec[r] = true
				recs = append(recs, r)
			}
		}
	}

	return Diagnosis{
		ProbableCause:   categoryTitles[topCat],
		Confidence:      confidence,
		Category:        topCat,
		Signals:         signalsByCat[topCat],
		Causes:          causes,
		Recommendations: recs,
	}
}
