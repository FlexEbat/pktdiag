package cmd

import (
	"fmt"
)

const usage = `pktdiag — диагностика сети через захват и анализ пакетов

Использование:
  pktdiag <команда> [флаги]

Команды:
  doctor                 Проверить окружение (tcpdump, tshark, права, диск)
  capture                Захватить трафик, собрать метаданные, построить отчёт и архив
  analyze <файл>         Захватить существующий pcap/архив и показать человекочитаемый обзор
  report  <файл>         Построить отчёт (html/json/md) по существующему pcap/архиву
  explain <термин>       Объяснить сетевой термин/метрику
  version                Показать версию

Примеры:
  pktdiag doctor
  pktdiag capture --iface eth0 --filter "tcp port 443" --duration 30s
  pktdiag capture --iface eth0 --duration 15s --output ./out
  pktdiag report ./out/capture.pcapng --format html
  pktdiag analyze ./out/capture.pcapng
  pktdiag explain retransmission
`

const version = "0.1.0-mvp"

// Execute разбирает первый аргумент как имя команды и делегирует её обработчику.
func Execute(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}

	switch args[0] {
	case "-h", "--help", "help":
		fmt.Print(usage)
		return nil
	case "version", "-v", "--version":
		fmt.Println("pktdiag", version)
		return nil
	case "doctor":
		return runDoctor(args[1:])
	case "capture", "collect", "bundle":
		return runCapture(args[1:])
	case "report":
		return runReport(args[1:])
	case "analyze", "open":
		return runAnalyze(args[1:])
	case "explain":
		return runExplain(args[1:])
	default:
		fmt.Print(usage)
		return fmt.Errorf("неизвестная команда: %s", args[0])
	}
}
