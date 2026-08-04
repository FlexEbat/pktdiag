// Package analyze оборачивает вызовы tshark/capinfos и превращает их
// текстовый вывод в структурированную статистику (Report).
package analyze

import (
	"bufio"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// requireTools проверяет, что нужные для анализа бинарники есть в PATH.
func requireTools() error {
	for _, bin := range []string{"tshark", "capinfos"} {
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("%s не найден в PATH, установите tshark/wireshark-common", bin)
		}
	}
	return nil
}

// capinfoSummary хранит базовые данные о файле захвата.
type capinfoSummary struct {
	Packets     int64
	DurationSec float64
}

func runCapinfos(pcapPath string) (capinfoSummary, error) {
	var sum capinfoSummary
	out, err := exec.Command("capinfos", "-c", "-u", "-M", "-T", pcapPath).Output()
	if err != nil {
		return sum, fmt.Errorf("capinfos: %w", err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) < 2 {
		return sum, fmt.Errorf("capinfos: неожиданный вывод: %q", string(out))
	}
	// Формат: File name<TAB>Number of packets<TAB>Capture duration (seconds)
	fields := strings.Split(lines[1], "\t")
	if len(fields) < 3 {
		return sum, fmt.Errorf("capinfos: не удалось разобрать строку: %q", lines[1])
	}
	sum.Packets, _ = strconv.ParseInt(strings.TrimSpace(fields[1]), 10, 64)
	sum.DurationSec, _ = strconv.ParseFloat(strings.TrimSpace(fields[2]), 64)
	return sum, nil
}

// countFilter возвращает число пакетов, подходящих под display filter tshark.
func countFilter(pcapPath, filter string) (int, error) {
	cmd := exec.Command("tshark", "-r", pcapPath, "-Y", filter, "-T", "fields", "-e", "frame.number")
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("tshark -Y %q: %w", filter, err)
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		return 0, nil
	}
	return len(strings.Split(strings.TrimRight(string(out), "\n"), "\n")), nil
}

// fieldValues возвращает значения указанного поля для пакетов, подходящих
// под display filter (используется, например, для dns.time).
func fieldValues(pcapPath, filter, field string) ([]float64, error) {
	cmd := exec.Command("tshark", "-r", pcapPath, "-Y", filter, "-T", "fields", "-e", field)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("tshark -Y %q -e %s: %w", filter, field, err)
	}
	var values []float64
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if v, err := strconv.ParseFloat(line, 64); err == nil {
			values = append(values, v)
		}
	}
	return values, nil
}

// runTsharkFields выполняет tshark -Y filter -T fields -e f1 -e f2 ...
// и возвращает построчно значения полей. По умолчанию разделитель полей: табуляция.
func runTsharkFields(pcapPath, filter string, fields ...string) ([][]string, error) {
	args := []string{"-r", pcapPath, "-Y", filter, "-T", "fields"}
	for _, f := range fields {
		args = append(args, "-e", f)
	}
	cmd := exec.Command("tshark", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("tshark -Y %q: %w", filter, err)
	}
	var rows [][]string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		rows = append(rows, strings.Split(line, "\t"))
	}
	return rows, nil
}

func avg(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func pct(part, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}
