package cmd

import (
	"fmt"

	"pktdiag/internal/analyze"
)

func runHealth(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("использование: pktdiag health <pcap|каталог|bundle.tar.zst>")
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

	fmt.Printf("Score\n  %d/100\n\n", rep.Health.Total)
	for _, comp := range []string{"network", "tcp", "dns"} {
		if v, ok := rep.Health.Components[comp]; ok {
			fmt.Printf("  %-8s %d\n", comp, v)
		}
	}
	return nil
}
