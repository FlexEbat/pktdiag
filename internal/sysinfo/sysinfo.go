// Package sysinfo собирает метаданные хоста без внешних зависимостей,
// используя exec(uname) и чтение файлов из /proc и /etc.
package sysinfo

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Interface описывает один сетевой интерфейс.
type Interface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac,omitempty"`
	State     string   `json:"state,omitempty"`
	MTU       int      `json:"mtu,omitempty"`
	RXBytes   int64    `json:"rx_bytes"`
	TXBytes   int64    `json:"tx_bytes"`
	Addresses []string `json:"addresses,omitempty"`
}

// SystemInfo — собранный снимок состояния хоста в момент захвата.
type SystemInfo struct {
	CollectedAt time.Time   `json:"collected_at"`
	Hostname    string      `json:"hostname"`
	Uname       string      `json:"uname"`
	Kernel      string      `json:"kernel"`
	OS          string      `json:"os"`
	Arch        string      `json:"arch"`
	CPUModel    string      `json:"cpu_model,omitempty"`
	CPUCount    int         `json:"cpu_count"`
	MemTotalKB  int64       `json:"mem_total_kb"`
	Interfaces  []Interface `json:"interfaces"`
	DNSServers  []string    `json:"dns_servers,omitempty"`
	RouteRaw    []string    `json:"routes_raw,omitempty"`
	Notes       []string    `json:"notes,omitempty"` // что не удалось собрать и почему
}

// Collect собирает информацию о текущей системе, стараясь не падать
// при отсутствии отдельных источников (например, если нет прав).
func Collect() SystemInfo {
	info := SystemInfo{
		CollectedAt: time.Now(),
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		CPUCount:    runtime.NumCPU(),
	}

	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}

	if out, err := exec.Command("uname", "-a").Output(); err == nil {
		info.Uname = strings.TrimSpace(string(out))
	} else {
		info.Notes = append(info.Notes, "uname недоступен: "+err.Error())
	}
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		info.Kernel = strings.TrimSpace(string(out))
	}

	if model, count, err := cpuInfo(); err == nil {
		info.CPUModel = model
		if count > 0 {
			info.CPUCount = count
		}
	} else {
		info.Notes = append(info.Notes, "не удалось прочитать /proc/cpuinfo: "+err.Error())
	}

	if kb, err := memTotalKB(); err == nil {
		info.MemTotalKB = kb
	} else {
		info.Notes = append(info.Notes, "не удалось прочитать /proc/meminfo: "+err.Error())
	}

	ifaces, err := interfaces()
	if err != nil {
		info.Notes = append(info.Notes, "не удалось получить список интерфейсов: "+err.Error())
	}
	info.Interfaces = ifaces

	info.DNSServers = dnsServers()

	if lines, err := routesRaw(); err == nil {
		info.RouteRaw = lines
	} else {
		info.Notes = append(info.Notes, "не удалось прочитать таблицу маршрутизации: "+err.Error())
	}

	return info
}

func cpuInfo() (model string, count int, err error) {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 && model == "" {
				model = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(line, "processor") {
			count++
		}
	}
	return model, count, sc.Err()
}

func memTotalKB() (int64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return strconv.ParseInt(fields[1], 10, 64)
			}
		}
	}
	return 0, fmt.Errorf("MemTotal не найден")
}

// interfaces читает /proc/net/dev для списка и счётчиков,
// а /sys/class/net/<iface>/{address,operstate,mtu} для деталей.
func interfaces() ([]Interface, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var result []Interface
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		if lineNum <= 2 {
			continue // заголовки
		}
		line := sc.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		rx, _ := strconv.ParseInt(fields[0], 10, 64)
		tx, _ := strconv.ParseInt(fields[8], 10, 64)

		iface := Interface{Name: name, RXBytes: rx, TXBytes: tx}
		iface.MAC = readSysFile(filepath.Join("/sys/class/net", name, "address"))
		iface.State = readSysFile(filepath.Join("/sys/class/net", name, "operstate"))
		if mtuStr := readSysFile(filepath.Join("/sys/class/net", name, "mtu")); mtuStr != "" {
			if mtu, err := strconv.Atoi(mtuStr); err == nil {
				iface.MTU = mtu
			}
		}
		result = append(result, iface)
	}
	return result, sc.Err()
}

func readSysFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func dnsServers() []string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var servers []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) == 2 {
				servers = append(servers, fields[1])
			}
		}
	}
	return servers
}

// routesRaw возвращает таблицу маршрутизации построчно как есть (без
// разбора hex-полей) — этого достаточно для отчёта/архива на первом этапе.
func routesRaw() ([]string, error) {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}

// AvailableInterfaces возвращает только имена интерфейсов — используется
// доктором и мастером выбора интерфейса при захвате.
func AvailableInterfaceNames() ([]string, error) {
	ifaces, err := interfaces()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(ifaces))
	for _, i := range ifaces {
		names = append(names, i.Name)
	}
	return names, nil
}
