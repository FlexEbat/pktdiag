package cmd

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"pktdiag/internal/doctorx"
)

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	install := fs.Bool("install", false, "предложить (или, с --yes, сразу выполнить) автоустановку недостающих пакетов")
	yes := fs.Bool("yes", false, "не спрашивать подтверждения перед автоустановкой (используется с --install)")
	if err := fs.Parse(reorderArgsForFlags(fs, args)); err != nil {
		return err
	}

	rep := doctorx.Run()

	fmt.Println("pktdiag doctor: проверка окружения")
	fmt.Println()
	for _, c := range rep.Checks {
		fmt.Printf("%s %-14s %s\n", c.Status.Symbol(), c.Name, c.Detail)
	}
	fmt.Println()

	missing := rep.MissingPackages()

	if rep.AllOK() && len(missing) == 0 {
		fmt.Println("Окружение готово к захвату трафика.")
		return nil
	}

	if rep.AllOK() {
		fmt.Println("Обязательные проверки пройдены, но есть необязательные пакеты, которых не хватает (⚠).")
	} else {
		fmt.Println("Есть проблемы (✘), которые нужно исправить перед захватом.")
	}

	if len(missing) == 0 {
		return nil
	}

	fmt.Printf("\nНедостающие пакеты: %s\n", strings.Join(missing, " "))

	if !*install {
		fmt.Println("Установить их автоматически: pktdiag doctor --install")
		fmt.Println("Или вручную: " + doctorx.ManualInstallHint(missing))
		return nil
	}

	if os.Geteuid() != 0 {
		fmt.Println("\nАвтоустановка требует root. Запустите: sudo pktdiag doctor --install")
		fmt.Println("Или вручную: " + doctorx.ManualInstallHint(missing))
		return nil
	}

	if !*yes {
		fmt.Printf("\nУстановить %s через %s? [y/N] ", strings.Join(missing, " "), doctorx.PackageManager())
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "y" && answer != "yes" && answer != "д" && answer != "да" {
			fmt.Println("Отменено. Установить вручную: " + doctorx.ManualInstallHint(missing))
			return nil
		}
	}

	fmt.Println()
	err := doctorx.Install(missing, func(line string) {
		fmt.Println("  " + line)
	})
	if err != nil {
		return fmt.Errorf("автоустановка не удалась: %w\nУстановите вручную: %s", err, doctorx.ManualInstallHint(missing))
	}

	fmt.Println("\nГотово. Перезапустите `pktdiag doctor`, чтобы убедиться, что всё подхватилось.")
	return nil
}
