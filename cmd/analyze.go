package cmd

import (
	"flag"
	"fmt"
	"path/filepath"

	"pktdiag/internal/analyze"
	"pktdiag/internal/explainx"
	"pktdiag/internal/report"
)

func runAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	save := fs.String("save", "", "дополнительно сохранить отчёт в форматах через запятую (html,json,md,pdf)")
	output := fs.String("output", "", "каталог для сохранения (используется вместе с --save)")
	explainAnomalies := fs.Bool("explain", false, "показать подробное объяснение по каждой найденной аномалии")
	if err := fs.Parse(reorderArgsForFlags(fs, args)); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("использование: pktdiag analyze <pcap|каталог|bundle.tar.zst> [--explain] [--save html,json,md,pdf]")
	}
	src := fs.Arg(0)

	rs, err := resolveSource(src)
	if err != nil {
		return err
	}
	defer rs.Cleanup()

	rep, err := analyze.Build(rs.PcapPath, nil)
	if err != nil {
		return err
	}
	rep.System = rs.System

	fmt.Println(report.TerminalSummary(rep))

	if *explainAnomalies && len(rep.Anomalies) > 0 {
		fmt.Println("Подробности")
		for _, a := range rep.Anomalies {
			if entry, ok := explainx.Lookup(a.ID); ok {
				fmt.Println(explainx.Format(entry))
			}
		}
	}

	if *save != "" {
		outDir := *output
		if outDir == "" {
			outDir = filepath.Dir(rs.PcapPath)
		}
		return writeReportFiles(rep, outDir, parseFormats(*save))
	}
	return nil
}
