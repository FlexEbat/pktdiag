// Package capture запускает tcpdump как подпроцесс и собирает
// стандартную итоговую статистику из его stderr.
package capture

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Options — параметры одного захвата.
type Options struct {
	Interface  string        // например "eth0" или "any"
	Filter     string        // BPF-фильтр, например "tcp port 443"; может быть пустым
	Duration   time.Duration // 0 — захват идёт, пока процесс не получит SIGINT снаружи
	OutputPcap string        // путь к файлу для записи (.pcapng/.pcap)
	Ring       RingOptions   // опционально — кольцевой буфер
	Snaplen    int           // 0 — без ограничения (tcpdump -s0)
}

// RingOptions — параметры кольцевого буфера (UC-04 из ТЗ).
type RingOptions struct {
	Enabled  bool
	FileMB   int // -C, размер одного файла в мегабайтах (десятичных, как у tcpdump)
	NumFiles int // -W, количество файлов в кольце
}

// Result — итог одного захвата.
type Result struct {
	StartedAt               time.Time
	EndedAt                 time.Time
	PacketsCaptured         int64
	PacketsReceivedByFilter int64
	PacketsDroppedByKernel  int64
	RawStderr               string
}

var summaryRe = regexp.MustCompile(`^(\d+)\s+packets\s+(captured|received by filter|dropped by kernel)`)

// FindRingFiles ищет файлы кольцевого буфера, которые tcpdump создаёт из
// basePath, добавляя числовой суффикс сразу к имени файла без разделителя
// (например, "capture.pcapng" -> "capture.pcapng0", "capture.pcapng1", ...).
// Возвращает пути, отсортированные по числовому суффиксу.
func FindRingFiles(basePath string) ([]string, error) {
	matches, err := filepath.Glob(basePath + "[0-9]*")
	if err != nil {
		return nil, err
	}
	sort.Slice(matches, func(i, j int) bool {
		return ringSuffixNum(matches[i], basePath) < ringSuffixNum(matches[j], basePath)
	})
	return matches, nil
}

func ringSuffixNum(path, basePath string) int {
	suffix := strings.TrimPrefix(path, basePath)
	n, err := strconv.Atoi(suffix)
	if err != nil {
		return 0
	}
	return n
}

// MergeRingFiles склеивает несколько файлов кольцевого буфера в один pcap
// через системный mergecap (часть пакета wireshark-common), чтобы можно
// было анализировать их как единый непрерывный поток.
func MergeRingFiles(files []string, mergedPath string) error {
	if len(files) == 0 {
		return fmt.Errorf("нет файлов для слияния")
	}
	if _, err := exec.LookPath("mergecap"); err != nil {
		return fmt.Errorf("mergecap не найден в PATH (пакет wireshark-common): %w", err)
	}
	args := append([]string{"-w", mergedPath}, files...)
	out, err := exec.Command("mergecap", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mergecap: %w\n%s", err, string(out))
	}
	return nil
}
func Run(opts Options) (Result, error) {
	var res Result

	if opts.Interface == "" {
		return res, fmt.Errorf("не указан интерфейс")
	}
	if opts.OutputPcap == "" {
		return res, fmt.Errorf("не указан путь для сохранения pcap")
	}

	args := []string{"-i", opts.Interface}
	if os.Geteuid() == 0 {
		// По умолчанию tcpdump на Ubuntu/Debian сбрасывает привилегии на
		// пользователя "tcpdump" сразу после открытия интерфейса. Это ломает
		// ring buffer: новые файлы кольца создаются уже без прав на запись
		// в каталог результатов (он создан от root с 0755). "-Z root"
		// отключает сброс привилегий, раз мы и так уже root.
		args = append(args, "-Z", "root")
	}
	if opts.Snaplen == 0 {
		args = append(args, "-s", "0")
	} else {
		args = append(args, "-s", strconv.Itoa(opts.Snaplen))
	}
	args = append(args, "-U") // писать пакеты сразу, не буферизуя

	if opts.Ring.Enabled {
		args = append(args, "-C", strconv.Itoa(opts.Ring.FileMB), "-W", strconv.Itoa(opts.Ring.NumFiles))
	}

	args = append(args, "-w", opts.OutputPcap)

	if strings.TrimSpace(opts.Filter) != "" {
		// Простое разбиение по пробелам — покрывает типовые фильтры
		// вида "tcp port 443", "host 10.0.0.1", "udp or icmp".
		args = append(args, strings.Fields(opts.Filter)...)
	}

	cmd := exec.Command("tcpdump", args...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return res, fmt.Errorf("не удалось получить stderr tcpdump: %w", err)
	}

	res.StartedAt = time.Now()
	if err := cmd.Start(); err != nil {
		return res, fmt.Errorf("не удалось запустить tcpdump: %w", err)
	}

	var stderrLines []string
	done := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			stderrLines = append(stderrLines, sc.Text())
		}
		close(done)
	}()

	if opts.Duration > 0 {
		timer := time.AfterFunc(opts.Duration, func() {
			_ = cmd.Process.Signal(syscall.SIGINT)
		})
		defer timer.Stop()
	}
	// Если Duration == 0, ожидаем, что пользователь сам пришлёт SIGINT
	// (Ctrl+C в терминале) — tcpdump в той же группе процессов получит
	// сигнал напрямую от терминала.

	waitErr := cmd.Wait()
	<-done
	res.EndedAt = time.Now()
	res.RawStderr = strings.Join(stderrLines, "\n")

	for _, line := range stderrLines {
		m := summaryRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		n, _ := strconv.ParseInt(m[1], 10, 64)
		switch m[2] {
		case "captured":
			res.PacketsCaptured = n
		case "received by filter":
			res.PacketsReceivedByFilter = n
		case "dropped by kernel":
			res.PacketsDroppedByKernel = n
		}
	}

	// tcpdump возвращает ненулевой код при обычном завершении по SIGINT —
	// это ожидаемо и не считается ошибкой, если мы получили сводку пакетов.
	if waitErr != nil && res.PacketsCaptured == 0 && res.PacketsReceivedByFilter == 0 {
		return res, fmt.Errorf("tcpdump завершился с ошибкой: %w\n%s", waitErr, res.RawStderr)
	}

	return res, nil
}
