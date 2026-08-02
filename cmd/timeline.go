package cmd

import (
	"fmt"

	"pktdiag/internal/analyze"
)

func runTimeline(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("использование: pktdiag timeline <pcap|каталог|bundle.tar.zst>")
	}
	rs, err := resolveSource(args[0])
	if err != nil {
		return err
	}
	defer rs.Cleanup()

	events, err := analyze.BuildTimeline(rs.PcapPath)
	if err != nil {
		return err
	}

	fmt.Print(analyze.FormatTimeline(events))
	return nil
}
