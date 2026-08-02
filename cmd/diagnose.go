package cmd

import (
	"fmt"

	"pktdiag/internal/analyze"
)

func runDiagnose(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("использование: pktdiag diagnose <pcap|каталог|bundle.tar.zst>")
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

	d := analyze.Diagnose(rep)

	fmt.Println("Вероятная причина")
	fmt.Println("  " + d.ProbableCause)
	fmt.Println()
	fmt.Printf("Уверенность\n  %d%%\n\n", d.Confidence)

	if len(d.Signals) > 0 {
		fmt.Println("Сигналы")
		for _, s := range d.Signals {
			fmt.Println("  • " + s)
		}
		fmt.Println()
	}
	if len(d.Causes) > 0 {
		fmt.Println("Возможные причины")
		for _, c := range d.Causes {
			fmt.Println("  • " + c)
		}
		fmt.Println()
	}
	if len(d.Recommendations) > 0 {
		fmt.Println("Рекомендации")
		for _, r := range d.Recommendations {
			fmt.Println("  • " + r)
		}
	}
	return nil
}
