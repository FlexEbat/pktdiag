package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"pktdiag/internal/sysinfo"
)

// resolvedSource — результат разбора аргумента-источника для report/analyze.
type resolvedSource struct {
	PcapPath string
	System   *sysinfo.SystemInfo // nil, если metadata.json не найден
	Cleanup  func()
}

// resolveSource принимает путь к .pcap/.pcapng, к каталогу с ними, либо
// к архиву .tar.zst (бандлу) и приводит его к пути конкретного pcap-файла,
// попутно подхватывая metadata.json, если он есть рядом (см. UC-08, UC-09).
func resolveSource(path string) (resolvedSource, error) {
	var res resolvedSource
	res.Cleanup = func() {}

	st, err := os.Stat(path)
	if err != nil {
		return res, fmt.Errorf("не удалось открыть %s: %w", path, err)
	}

	switch {
	case st.IsDir():
		pcap, err := findPcapInDir(path)
		if err != nil {
			return res, err
		}
		res.PcapPath = pcap
		res.System = loadMetadataIfPresent(path)
		return res, nil

	case strings.HasSuffix(path, ".tar.zst") || strings.HasSuffix(path, ".tzst"):
		tmpDir, err := os.MkdirTemp("", "pktdiag-bundle-*")
		if err != nil {
			return res, fmt.Errorf("mkdtemp: %w", err)
		}
		if _, err := exec.LookPath("tar"); err != nil {
			os.RemoveAll(tmpDir)
			return res, fmt.Errorf("tar не найден в PATH — не могу распаковать бандл")
		}
		cmd := exec.Command("tar", "--zstd", "-xf", path, "-C", tmpDir)
		if out, err := cmd.CombinedOutput(); err != nil {
			os.RemoveAll(tmpDir)
			return res, fmt.Errorf("не удалось распаковать бандл: %w\n%s", err, string(out))
		}
		pcap, err := findPcapInDir(tmpDir)
		if err != nil {
			os.RemoveAll(tmpDir)
			return res, err
		}
		res.PcapPath = pcap
		res.System = loadMetadataIfPresent(tmpDir)
		res.Cleanup = func() { os.RemoveAll(tmpDir) }
		return res, nil

	default:
		res.PcapPath = path
		res.System = loadMetadataIfPresent(filepath.Dir(path))
		return res, nil
	}
}

func findPcapInDir(dir string) (string, error) {
	var candidates []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("не удалось прочитать каталог %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".pcapng") || strings.HasSuffix(name, ".pcap") {
			candidates = append(candidates, filepath.Join(dir, name))
		}
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("в %s не найдено *.pcap/*.pcapng файлов", dir)
	}
	return candidates[0], nil
}

func loadMetadataIfPresent(dir string) *sysinfo.SystemInfo {
	b, err := os.ReadFile(filepath.Join(dir, "metadata.json"))
	if err != nil {
		return nil
	}
	var si sysinfo.SystemInfo
	if err := json.Unmarshal(b, &si); err != nil {
		return nil
	}
	return &si
}

// reorderArgsForFlags переставляет аргументы так, чтобы все флаги (и их
// значения) шли перед позиционными аргументами. Это нужно потому, что
// стандартный пакет flag прекращает разбор флагов при первом позиционном
// аргументе, а в pktdiag команды часто выглядят как
// "pktdiag report file.pcap --format md" (флаг после позиционного аргумента).
func reorderArgsForFlags(fs *flag.FlagSet, args []string) []string {
	var flagArgs, positional []string

	isBoolFlag := func(name string) bool {
		fl := fs.Lookup(name)
		if fl == nil {
			return false
		}
		bf, ok := fl.Value.(interface{ IsBoolFlag() bool })
		return ok && bf.IsBoolFlag()
	}

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(a) > 0 && a[0] == '-' {
			name := strings.TrimLeft(a, "-")
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				// значение уже приклеено через "=" — отдельный токен не нужен
				flagArgs = append(flagArgs, a)
				continue
			}
			flagArgs = append(flagArgs, a)
			if !isBoolFlag(name) && i+1 < len(args) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
			continue
		}
		positional = append(positional, a)
	}

	return append(flagArgs, positional...)
}

// parseFormats разбирает "html,json,md,pdf" в множество форматов, по умолчанию html+json.
func parseFormats(s string) map[string]bool {
	out := map[string]bool{}
	if strings.TrimSpace(s) == "" {
		return map[string]bool{"html": true, "json": true}
	}
	for _, f := range strings.Split(s, ",") {
		out[strings.TrimSpace(f)] = true
	}
	return out
}
