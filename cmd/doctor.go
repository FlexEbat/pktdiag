package cmd

import (
	"fmt"

	"pktdiag/internal/doctorx"
)

func runDoctor(args []string) error {
	rep := doctorx.Run()

	fmt.Println("pktdiag doctor — проверка окружения")
	fmt.Println()
	for _, c := range rep.Checks {
		fmt.Printf("%s %-14s %s\n", c.Status.Symbol(), c.Name, c.Detail)
	}
	fmt.Println()
	if rep.AllOK() {
		fmt.Println("Окружение готово к захвату трафика.")
		return nil
	}
	fmt.Println("Есть проблемы (✘), которые нужно исправить перед захватом.")
	return nil
}
