package cmd

import (
	"fmt"
)

const usage = `pktdiag — диагностика сети через захват и анализ пакетов

Использование:
  pktdiag <команда> [флаги]

Команды:
  doctor                 Проверить окружение (tcpdump, tshark, права, диск); --install — предложить/выполнить автоустановку недостающих пакетов
  capture                Захватить трафик, собрать метаданные, построить отчёт и архив
  analyze <файл>         Захватить существующий pcap/архив и показать человекочитаемый обзор
  report  <файл>         Построить отчёт (html/json/md) по существующему pcap/архиву
  explain <термин>       Объяснить сетевой термин/метрику
  diagnose <файл>        Автоматический диагноз: вероятная причина + уверенность
  timeline <файл>        Хронология аномалий (retransmission/reset/dns error/...)
  inspect <файл>         Быстрый чек-лист TCP/DNS/TLS (MSS, Window Scale, Alerts, ...)
  compare <до> <после>   Сравнить два захвата (RTT/DNS/drops/retransmission/score)
  health <файл>          Показать только Health Score
  version                Показать версию

Примеры:
  pktdiag doctor
  pktdiag capture --iface eth0 --filter "tcp port 443" --duration 30s
  pktdiag capture --iface eth0 --duration 15s --output ./out
  pktdiag capture --config pktdiag.yaml
  pktdiag report ./out/capture.pcapng --format html
  pktdiag analyze ./out/capture.pcapng
  pktdiag explain retransmission
  pktdiag diagnose ./out/capture.pcapng
  pktdiag timeline ./out/capture.pcapng
  pktdiag inspect ./out/capture.pcapng
  pktdiag compare ./before.tar.zst ./after.tar.zst
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
	case "diagnose":
		return runDiagnose(args[1:])
	case "timeline":
		return runTimeline(args[1:])
	case "inspect":
		return runInspect(args[1:])
	case "compare":
		return runCompare(args[1:])
	case "health":
		return runHealth(args[1:])
	default:
		fmt.Print(usage)
		return fmt.Errorf("неизвестная команда: %s", args[0])
	}
}
