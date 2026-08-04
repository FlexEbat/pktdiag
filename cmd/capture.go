package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"pktdiag/internal/analyze"
	"pktdiag/internal/archive"
	"pktdiag/internal/capture"
	"pktdiag/internal/doctorx"
	"pktdiag/internal/report"
	"pktdiag/internal/sysinfo"
	"pktdiag/internal/yamlcfg"
)

func runCapture(args []string) error {
	// Конфиг грузим до определения флагов, чтобы его значения стали
	// дефолтами. Явные флаги командной строки переопределяют их
	// (см. pktdiag.example.yaml).
	cfgPath := extractConfigPath(args)
	var cfg yamlcfg.Config
	if cfgPath != "" {
		loaded, err := yamlcfg.Load(cfgPath)
		if err != nil {
			return fmt.Errorf("не удалось прочитать конфиг %s: %w", cfgPath, err)
		}
		cfg = loaded
		fmt.Printf("Конфиг: %s\n", cfgPath)
	}

	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	_ = fs.String("config", "", "путь к YAML-конфигу, по умолчанию ./pktdiag.yaml, если существует")
	iface := fs.String("iface", cfg.Get("capture", "iface", ""), "сетевой интерфейс, по умолчанию автовыбор без lo")
	filter := fs.String("filter", cfg.Get("capture", "filter", ""), `BPF-фильтр tcpdump, например "tcp port 443"`)
	duration := fs.String("duration", cfg.Get("capture", "duration", "30s"), `длительность захвата, например "30s", "5m". "0" значит до Ctrl+C`)
	output := fs.String("output", cfg.Get("capture", "output", ""), "каталог для результатов, по умолчанию ./pktdiag-capture-<timestamp>")
	format := fs.String("format", cfg.Get("report", "format", "html,json"), "форматы отчёта через запятую: html,json,md,pdf")
	noArchive := fs.Bool("no-archive", !cfg.GetBool("report", "archive", true), "не собирать финальный tar.zst архив")
	ring := fs.Int("ring", cfg.GetInt("capture", "ring", 0), "включить кольцевой буфер: количество файлов, 0 выключает")
	ringSize := fs.Int("ring-size", cfg.GetInt("capture", "ring_size", 100), "размер одного файла кольцевого буфера, МБ")
	snaplen := fs.Int("snaplen", cfg.GetInt("capture", "snaplen", 0), "snapshot length tcpdump, 0 значит без ограничения (-s0)")
	force := fs.Bool("force", false, "продолжить, даже если doctor нашёл проблемы (✘)")
	if err := fs.Parse(reorderArgsForFlags(fs, args)); err != nil {
		return err
	}

	// 1. Проверка окружения
	docRep := doctorx.Run()
	if !docRep.AllOK() && !*force {
		fmt.Println("doctor нашёл проблемы, захват остановлен (используйте --force, чтобы продолжить всё равно):")
		for _, c := range docRep.Checks {
			if c.Status == doctorx.Fail {
				fmt.Printf("  %s %s: %s\n", c.Status.Symbol(), c.Name, c.Detail)
			}
		}
		return fmt.Errorf("окружение не готово")
	}

	// 2. Интерфейс
	selectedIface := *iface
	if selectedIface == "" {
		names, err := sysinfo.AvailableInterfaceNames()
		if err != nil || len(names) == 0 {
			selectedIface = "any"
		} else {
			selectedIface = pickDefaultInterface(names)
		}
		fmt.Printf("Интерфейс не указан, выбран автоматически: %s\n", selectedIface)
	}

	// 3. Длительность
	var dur time.Duration
	if *duration != "0" && *duration != "" {
		d, err := time.ParseDuration(*duration)
		if err != nil {
			return fmt.Errorf("некорректная длительность %q: %w", *duration, err)
		}
		dur = d
	}

	// 4. Каталог результатов
	outDir := *output
	if outDir == "" {
		outDir = fmt.Sprintf("pktdiag-capture-%s", time.Now().Format("2006-01-02-150405"))
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("не удалось создать каталог %s: %w", outDir, err)
	}

	// 5. Метаданные системы (до захвата)
	sysInfo := sysinfo.Collect()
	if err := writeJSONFile(filepath.Join(outDir, "metadata.json"), sysInfo); err != nil {
		fmt.Fprintln(os.Stderr, "предупреждение: не удалось сохранить metadata.json:", err)
	}

	// 6. Захват
	pcapPath := filepath.Join(outDir, "capture.pcapng")
	fmt.Printf("Захват: iface=%s filter=%q duration=%s -> %s\n", selectedIface, *filter, *duration, pcapPath)

	copts := capture.Options{
		Interface:  selectedIface,
		Filter:     *filter,
		Duration:   dur,
		OutputPcap: pcapPath,
		Snaplen:    *snaplen,
	}
	if *ring > 0 {
		copts.Ring = capture.RingOptions{Enabled: true, FileMB: *ringSize, NumFiles: *ring}
	}

	capRes, err := capture.Run(copts)
	if err != nil {
		return fmt.Errorf("захват не удался: %w", err)
	}
	fmt.Printf("Готово: captured=%d received=%d dropped=%d (%.1fs)\n",
		capRes.PacketsCaptured, capRes.PacketsReceivedByFilter, capRes.PacketsDroppedByKernel,
		capRes.EndedAt.Sub(capRes.StartedAt).Seconds())

	if *ring > 0 {
		ringFiles, err := capture.FindRingFiles(pcapPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "предупреждение: не удалось найти файлы кольцевого буфера:", err)
		}
		if len(ringFiles) == 0 {
			fmt.Println("Кольцевой буфер включён, но файлы с числовым суффиксом не найдены. Анализирую как есть.")
		} else {
			fmt.Printf("Кольцевой буфер: найдено %d файлов (%v), сливаю через mergecap для анализа.\n", len(ringFiles), ringFiles)
			merged := filepath.Join(outDir, "capture.merged.pcapng")
			if err := capture.MergeRingFiles(ringFiles, merged); err != nil {
				fmt.Fprintln(os.Stderr, "предупреждение: слияние файлов кольца не удалось, анализирую только базовый файл:", err)
			} else {
				pcapPath = merged
				fmt.Println("Объединённый файл для анализа: " + merged)
			}
		}
	}

	// 7. Анализ и отчёт
	captureInfo := &report.CaptureInfo{
		Interface:         selectedIface,
		Filter:            *filter,
		DurationRequested: *duration,
		StartedAt:         capRes.StartedAt,
		EndedAt:           capRes.EndedAt,
		PacketsReceived:   capRes.PacketsReceivedByFilter,
		PacketsDropped:    capRes.PacketsDroppedByKernel,
	}

	rep, err := analyze.Build(pcapPath, captureInfo)
	if err != nil {
		return fmt.Errorf("анализ не удался: %w", err)
	}
	rep.System = &sysInfo
	analyze.AddSystemChecks(&rep)

	if err := writeReportFiles(rep, outDir, parseFormats(*format)); err != nil {
		return err
	}

	// 8. Архив
	if !*noArchive {
		archivePath := outDir + ".tar.zst"
		if err := archive.CreateTarZst(outDir, archivePath); err != nil {
			fmt.Fprintln(os.Stderr, "предупреждение: не удалось собрать архив:", err)
		} else {
			fmt.Println("Архив: " + archivePath)
		}
	}

	return nil
}

// pickDefaultInterface выбирает первый интерфейс, не являющийся loopback.
func pickDefaultInterface(names []string) string {
	for _, n := range names {
		if n != "lo" {
			return n
		}
	}
	return names[0]
}

func writeJSONFile(path string, v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
