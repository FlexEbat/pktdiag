package cmd

import (
	"fmt"

	"pktdiag/internal/analyze"
	"pktdiag/internal/report"
)

func runCompare(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("использование: pktdiag compare <до> <после>")
	}

	before, err := buildReportFromSource(args[0])
	if err != nil {
		return fmt.Errorf("до: %w", err)
	}
	after, err := buildReportFromSource(args[1])
	if err != nil {
		return fmt.Errorf("после: %w", err)
	}

	fmt.Printf("%-22s %12s %12s %14s\n", "Метрика", "До", "После", "Δ")
	printCompareRow("RTT avg (мс)", before.RTT.AvgMs, after.RTT.AvgMs)
	printCompareRow("DNS avg (мс)", before.DNS.AvgResponseMs, after.DNS.AvgResponseMs)
	printCompareRow("Retransmission %", before.TCP.RetransmissionPct, after.TCP.RetransmissionPct)
	printCompareRowInt("Retransmission #", before.TCP.Retransmissions, after.TCP.Retransmissions)
	printCompareRowInt("Zero Window", before.TCP.ZeroWindow, after.TCP.ZeroWindow)
	printCompareRowInt("Resets", before.TCP.Resets, after.TCP.Resets)
	printCompareRowInt64("Dropped (capture)", dropped(before), dropped(after))
	printCompareRow("Avg PPS", before.Summary.AvgPPS, after.Summary.AvgPPS)
	printCompareRowInt("Health Score", before.Health.Total, after.Health.Total)

	return nil
}

func dropped(r report.Report) int64 {
	if r.Capture == nil {
		return 0
	}
	return r.Capture.PacketsDropped
}

func printCompareRow(label string, before, after float64) {
	delta := after - before
	sign := "+"
	if delta < 0 {
		sign = ""
	}
	fmt.Printf("%-22s %12.1f %12.1f %13s%.1f\n", label, before, after, sign, delta)
}

func printCompareRowInt(label string, before, after int) {
	delta := after - before
	sign := "+"
	if delta < 0 {
		sign = ""
	}
	fmt.Printf("%-22s %12d %12d %13s%d\n", label, before, after, sign, delta)
}

func printCompareRowInt64(label string, before, after int64) {
	delta := after - before
	sign := "+"
	if delta < 0 {
		sign = ""
	}
	fmt.Printf("%-22s %12d %12d %13s%d\n", label, before, after, sign, delta)
}

func buildReportFromSource(src string) (report.Report, error) {
	rs, err := resolveSource(src)
	if err != nil {
		return report.Report{}, err
	}
	defer rs.Cleanup()

	rep, err := analyze.Build(rs.PcapPath, nil)
	if err != nil {
		return report.Report{}, err
	}
	rep.System = rs.System
	return rep, nil
}
