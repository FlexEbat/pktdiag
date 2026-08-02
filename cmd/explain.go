package cmd

import (
	"fmt"
	"strings"

	"pktdiag/internal/explainx"
)

func runExplain(args []string) error {
	if len(args) == 0 {
		fmt.Println("Использование: pktdiag explain <термин>")
		fmt.Println()
		fmt.Println("Известные термины:")
		fmt.Println("  " + strings.Join(explainx.All(), ", "))
		return nil
	}

	term := strings.Join(args, " ")
	entry, ok := explainx.Lookup(term)
	if !ok {
		fmt.Printf("Термин %q не найден.\n\n", term)
		fmt.Println("Известные термины:")
		fmt.Println("  " + strings.Join(explainx.All(), ", "))
		return nil
	}

	fmt.Print(explainx.Format(entry))
	return nil
}
