package cmd

import (
	"flag"
	"fmt"
	"path/filepath"

	"pktdiag/internal/analyze"
	"pktdiag/internal/report"
)

func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	format := fs.String("format", "html,json", "форматы отчёта через запятую: html,json,md")
	output := fs.String("output", "", "каталог для сохранения отчёта (по умолчанию — рядом с источником)")
	if err := fs.Parse(reorderArgsForFlags(fs, args)); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("использование: pktdiag report <pcap|каталог|bundle.tar.zst> [--format html,json,md] [--output dir]")
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

	outDir := *output
	if outDir == "" {
		outDir = filepath.Dir(rs.PcapPath)
	}

	return writeReportFiles(rep, outDir, parseFormats(*format))
}

func writeReportFiles(rep report.Report, outDir string, formats map[string]bool) error {
	var written []string
	if formats["json"] {
		p := filepath.Join(outDir, "report.json")
		if err := report.WriteJSON(rep, p); err != nil {
			return err
		}
		written = append(written, p)
	}
	if formats["html"] {
		p := filepath.Join(outDir, "report.html")
		if err := report.WriteHTML(rep, p); err != nil {
			return err
		}
		written = append(written, p)
	}
	if formats["md"] {
		p := filepath.Join(outDir, "report.md")
		if err := report.WriteMarkdown(rep, p); err != nil {
			return err
		}
		written = append(written, p)
	}

	fmt.Println(report.TerminalSummary(rep))
	fmt.Println("Сохранено:")
	for _, p := range written {
		fmt.Println("  " + p)
	}
	return nil
}
