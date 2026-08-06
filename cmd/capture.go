package cmd

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"

	"pktdiag/internal/analyze"
	"pktdiag/internal/archive"
	"pktdiag/internal/capture"
	"pktdiag/internal/doctorx"
	"pktdiag/internal/report"
	"pktdiag/internal/sysinfo"
)

func runCapture(args []string) error {
	// Конфиг грузим до определения флагов, чтобы его значения стали
	// дефолтами. Явные флаги командной строки переопределяют их
	// (см. pktdiag.example.yaml).
	cfgPath := extractConfigPath(args)
	v := viper.New()
	if cfgPath != "" {
		v.SetConfigFile(cfgPath)
		if err := v.ReadInConfig(); err != nil {
			return fmt.Errorf("не удалось прочитать конфиг %s: %w", cfgPath, err)
		}
		fmt.Printf("Конфиг: %s\n", cfgPath)
	}

	// Viper.GetString/GetBool/GetInt возвращают нулевое значение типа для
	// отсутствующего ключа, а не переданный по месту вызова дефолт, как
	// было у yamlcfg.Config.Get. IsSet отличает "ключа нет" от "ключ
	// явно выставлен в нулевое значение" (например, capture.ring: 0).
	getString := func(key, def string) string {
		if v.IsSet(key) {
			return v.GetString(key)
		}
		return def
	}
	getInt := func(key string, def int) int {
		if v.IsSet(key) {
			return v.GetInt(key)
		}
		return def
	}
	getBool := func(key string, def bool) bool {
		if v.IsSet(key) {
			return v.GetBool(key)
		}
		return def
	}

	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	_ = fs.String("config", "", "путь к YAML-конфигу, по умолчанию ./pktdiag.yaml, если существует")
	iface := fs.String("iface", getString("capture.iface", ""), "сетевой интерфейс, по умолчанию автовыбор без lo")
	filter := fs.String("filter", getString("capture.filter", ""), `BPF-фильтр tcpdump, например "tcp port 443"`)
	duration := fs.String("duration", getString("capture.duration", "30s"), `длительность захвата, например "30s", "5m". "0" значит до Ctrl+C`)
	output := fs.String("output", getString("capture.output", ""), "каталог для результатов, по умолчанию ./pktdiag-capture-<timestamp>")
	format := fs.String("format", getString("report.format", "html,json"), "форматы отчёта через запятую: html,json,md,pdf")
	noArchive := fs.Bool("no-archive", !getBool("report.archive", true), "не собирать финальный tar.zst архив")
	ring := fs.Int("ring", getInt("capture.ring", 0), "включить кольцевой буфер: количество файлов, 0 выключает")
	ringSize := fs.Int("ring-size", getInt("capture.ring_size", 100), "размер одного файла кольцевого буфера, МБ")
	snaplen := fs.Int("snaplen", getInt("capture.snaplen", 0), "snapshot length tcpdump, 0 значит без ограничения (-s0)")
	maxSize := fs.String("max-size", getString("capture.max_size", ""), `остановить захват в один файл по размеру, например "500MB", "2GB" (UC-03, без ring buffer)`)
	open := fs.Bool("open", getBool("capture.open", false), "открыть pcap в Wireshark после захвата, требует GUI-окружение")
	interactive := fs.Bool("interactive", false, "пошаговый мастер выбора интерфейса, фильтра и длительности вместо флагов")
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

	// 2. Интерфейс, фильтр, длительность: мастер или флаги
	var selectedIface, filterStr, durationStr string
	if *interactive {
		names, _ := sysinfo.AvailableInterfaceNames()
		wIface, wFilter, wDuration, err := runCaptureWizard(names)
		if err != nil {
			return err
		}
		selectedIface, filterStr, durationStr = wIface, wFilter, wDuration
	} else {
		selectedIface = *iface
		filterStr = *filter
		durationStr = *duration
	}

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
	if durationStr != "0" && durationStr != "" {
		d, err := time.ParseDuration(durationStr)
		if err != nil {
			return fmt.Errorf("некорректная длительность %q: %w", durationStr, err)
		}
		dur = d
	}

	// 3b. Максимальный размер одного файла (UC-03, без ring buffer)
	var maxSizeBytes int64
	if strings.TrimSpace(*maxSize) != "" {
		if *ring > 0 {
			return fmt.Errorf("--max-size и --ring взаимоисключающие: ring buffer сам ограничивает размер файла через --ring-size")
		}
		n, err := parseSize(*maxSize)
		if err != nil {
			return err
		}
		maxSizeBytes = n
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
	fmt.Printf("Захват: iface=%s filter=%q duration=%s -> %s\n", selectedIface, filterStr, durationStr, pcapPath)

	copts := capture.Options{
		Interface:    selectedIface,
		Filter:       filterStr,
		Duration:     dur,
		OutputPcap:   pcapPath,
		Snaplen:      *snaplen,
		MaxSizeBytes: maxSizeBytes,
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
		Filter:            filterStr,
		DurationRequested: durationStr,
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

	// 9. Открыть в Wireshark
	if *open {
		if err := openInWireshark(pcapPath); err != nil {
			fmt.Fprintln(os.Stderr, "предупреждение: не удалось открыть Wireshark:", err)
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

// openInWireshark запускает Wireshark на готовом pcap. Не блокирует
// pktdiag ожиданием закрытия окна: Wireshark продолжает работать после
// завершения pktdiag (UC-06 в ТЗ).
func openInWireshark(pcapPath string) error {
	bin, err := exec.LookPath("wireshark")
	if err != nil {
		return fmt.Errorf("wireshark не найден в PATH, установите пакет wireshark-qt или wireshark-gtk")
	}
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		fmt.Println("предупреждение: DISPLAY/WAYLAND_DISPLAY не установлены, Wireshark может не запуститься без GUI-окружения")
	}
	cmd := exec.Command(bin, pcapPath)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("запуск wireshark: %w", err)
	}
	fmt.Printf("Wireshark запущен (PID %d): %s\n", cmd.Process.Pid, pcapPath)
	return nil
}

// parseSize разбирает человекочитаемый размер вида "500MB", "2GB", "100K"
// в байты. Использует десятичные единицы СИ (1MB = 1_000_000 байт), как
// у самого tcpdump в -C, а не двоичные (MiB).
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	upper := strings.ToUpper(s)

	units := []struct {
		suffix string
		mult   float64
	}{
		{"GB", 1_000_000_000},
		{"G", 1_000_000_000},
		{"MB", 1_000_000},
		{"M", 1_000_000},
		{"KB", 1_000},
		{"K", 1_000},
		{"B", 1},
	}

	for _, u := range units {
		if strings.HasSuffix(upper, u.suffix) {
			numPart := strings.TrimSpace(s[:len(s)-len(u.suffix)])
			n, err := strconv.ParseFloat(numPart, 64)
			if err != nil {
				return 0, fmt.Errorf("некорректный размер %q: %w", s, err)
			}
			return int64(n * u.mult), nil
		}
	}

	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("некорректный размер %q, ожидался формат вида 500MB/2GB: %w", s, err)
	}
	return int64(n), nil
}

// runCaptureWizard проводит пользователя через выбор интерфейса, фильтра
// и длительности пошагово (см. раздел "Первый этап, Capture" в ТЗ).
// Возвращает интерфейс, BPF-фильтр и строку длительности, совместимую
// с --duration.
func runCaptureWizard(interfaces []string) (iface, filter, duration string, err error) {
	reader := bufio.NewReader(os.Stdin)

	ifaceOptions := append([]string{}, interfaces...)
	ifaceOptions = append(ifaceOptions, "any")
	fmt.Println("Выберите интерфейс:")
	for i, name := range ifaceOptions {
		fmt.Printf("  %d) %s\n", i+1, name)
	}
	idx := promptChoice(reader, "Ваш выбор", 1, len(ifaceOptions), 1)
	iface = ifaceOptions[idx-1]

	fmt.Println("\nФильтр:")
	filterLabels := []string{"без фильтра", "tcp", "udp", "icmp", "свой вариант"}
	for i, label := range filterLabels {
		fmt.Printf("  %d) %s\n", i+1, label)
	}
	fidx := promptChoice(reader, "Ваш выбор", 1, len(filterLabels), 1)
	switch fidx {
	case 1:
		filter = ""
	case 5:
		fmt.Print("Введите свой BPF-фильтр: ")
		line, _ := reader.ReadString('\n')
		filter = strings.TrimSpace(line)
	default:
		filter = filterLabels[fidx-1]
	}

	fmt.Println("\nПродолжительность:")
	durLabels := []string{"60 сек", "5 мин", "10 мин", "без ограничения (до Ctrl+C)", "свой вариант"}
	durValues := []string{"60s", "5m", "10m", "0", ""}
	for i, label := range durLabels {
		fmt.Printf("  %d) %s\n", i+1, label)
	}
	didx := promptChoice(reader, "Ваш выбор", 1, len(durLabels), 1)
	if didx == 5 {
		fmt.Print("Введите длительность, например 45s или 2m: ")
		line, _ := reader.ReadString('\n')
		duration = strings.TrimSpace(line)
	} else {
		duration = durValues[didx-1]
	}
	fmt.Println()

	return iface, filter, duration, nil
}

// promptChoice печатает приглашение, читает строку из reader и возвращает
// выбранный номер в диапазоне [min, max]. Пустой ввод или некорректное
// значение возвращают def.
func promptChoice(reader *bufio.Reader, label string, min, max, def int) int {
	fmt.Printf("%s [%d]: ", label, def)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	n, err := strconv.Atoi(line)
	if err != nil || n < min || n > max {
		return def
	}
	return n
}
