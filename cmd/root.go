package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

const version = "0.1.0-mvp"

const usage = `pktdiag: диагностика сети через захват и анализ пакетов

Использование:
  pktdiag <команда> [флаги]

Команды:
  doctor                 Проверить окружение (tcpdump, tshark, права, диск); --install ставит недостающие пакеты
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
  pktdiag capture --interactive
  pktdiag capture --max-size 500MB
  pktdiag capture --open
  pktdiag report ./out/capture.pcapng --format html
  pktdiag analyze ./out/capture.pcapng
  pktdiag explain retransmission
  pktdiag diagnose ./out/capture.pcapng
  pktdiag timeline ./out/capture.pcapng
  pktdiag inspect ./out/capture.pcapng
  pktdiag compare ./before.tar.zst ./after.tar.zst
`

// rootCmd маршрутизирует подкоманды через Cobra, но не через её парсер
// флагов: каждая подкоманда помечена DisableFlagParsing и получает сырые
// аргументы, которые дальше разбирает уже проверенный flag.FlagSet внутри
// runXxx. Так Cobra даёт дерево команд, --help верхнего уровня и
// автодополнение, не требуя переписывать разбор флагов в десяти файлах
// заново.
var rootCmd = &cobra.Command{
	Use:           "pktdiag",
	Short:         "Диагностика сети через захват и анализ пакетов",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args:          cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Print(usage)
	},
}

func passthrough(run func(args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		return run(args)
	}
}

func newLeafCmd(use, short string, run func(args []string) error) *cobra.Command {
	return &cobra.Command{
		Use:                use,
		Short:              short,
		DisableFlagParsing: true,
		RunE:               passthrough(run),
	}
}

func init() {
	rootCmd.AddCommand(
		newLeafCmd("doctor", "Проверить окружение (tcpdump, tshark, права, диск)", runDoctor),
		newLeafCmd("capture", "Захватить трафик, собрать метаданные, построить отчёт и архив", runCapture),
		newLeafCmd("collect", "Синоним capture", runCapture),
		newLeafCmd("bundle", "Синоним capture", runCapture),
		newLeafCmd("report", "Построить отчёт по существующему pcap/архиву", runReport),
		newLeafCmd("analyze", "Показать человекочитаемый обзор существующего pcap/архива", runAnalyze),
		newLeafCmd("open", "Синоним analyze", runAnalyze),
		newLeafCmd("explain", "Объяснить сетевой термин/метрику", runExplain),
		newLeafCmd("diagnose", "Автоматический диагноз: вероятная причина и уверенность", runDiagnose),
		newLeafCmd("timeline", "Хронология аномалий", runTimeline),
		newLeafCmd("inspect", "Быстрый чек-лист TCP/DNS/TLS", runInspect),
		newLeafCmd("compare", "Сравнить два захвата", runCompare),
		newLeafCmd("health", "Показать только Health Score", runHealth),
		&cobra.Command{
			Use:   "version",
			Short: "Показать версию",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("pktdiag", version)
				return nil
			},
		},
	)
}

// Execute разбирает args и запускает соответствующую подкоманду.
func Execute(args []string) error {
	rootCmd.SetArgs(args)
	return rootCmd.Execute()
}
