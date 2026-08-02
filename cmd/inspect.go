package cmd

import (
	"fmt"

	"pktdiag/internal/analyze"
)

func runInspect(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("использование: pktdiag inspect <pcap|каталог|bundle.tar.zst>")
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

	items, err := analyze.InspectFromReport(rs.PcapPath,
		rep.Protocols.TCP, rep.Protocols.DNS, rep.Protocols.TLS,
		rep.TCP.Retransmissions, rep.TCP.ZeroWindow)
	if err != nil {
		return err
	}

	lastGroup := ""
	for _, it := range items {
		if it.Group != lastGroup {
			fmt.Println()
			fmt.Println(it.Group)
			lastGroup = it.Group
		}
		mark := "✔"
		if !it.OK {
			mark = "⚠"
		}
		fmt.Printf("  %s %-16s %s\n", mark, it.Name, it.Detail)
	}
	fmt.Println()
	return nil
}
