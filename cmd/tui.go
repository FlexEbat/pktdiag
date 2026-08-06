package cmd

import (
	"fmt"

	"pktdiag/internal/analyze"
	"pktdiag/internal/tui"
)

func runTUI(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("использование: pktdiag tui <pcap|каталог|bundle.tar.zst>")
	}

	rs, err := resolveSource(args[0])
	if err != nil {
		return err
	}
	defer rs.Cleanup()

	rep, err := analyze.Build(rs.PcapPath, nil)
	if err != nil {
		return err
	}
	rep.System = rs.System
	analyze.AddSystemChecks(&rep)

	return tui.Run(rep)
}
