// Package doctorx реализует проверки окружения перед захватом трафика.
package doctorx

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"pktdiag/internal/sysinfo"
)

// Status — результат одной проверки.
type Status int

const (
	OK Status = iota
	Warn
	Fail
)

func (s Status) Symbol() string {
	switch s {
	case OK:
		return "✔"
	case Warn:
		return "⚠"
	default:
		return "✘"
	}
}

// Check — одна строка отчёта doctor.
type Check struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Report — сводный отчёт doctor.
type Report struct {
	Checks []Check `json:"checks"`
}

// Run выполняет все проверки окружения.
func Run() Report {
	var r Report

	r.Checks = append(r.Checks, binCheck("tcpdump", true))
	r.Checks = append(r.Checks, binCheck("dumpcap", false))
	r.Checks = append(r.Checks, binCheck("tshark", true))
	r.Checks = append(r.Checks, binCheck("capinfos", false))
	r.Checks = append(r.Checks, binCheck("zstd", false))
	r.Checks = append(r.Checks, binCheck("wkhtmltopdf", false))

	r.Checks = append(r.Checks, permissionCheck())
	r.Checks = append(r.Checks, diskSpaceCheck("."))
	r.Checks = append(r.Checks, interfacesCheck())

	return r
}

func binCheck(name string, required bool) Check {
	path, err := exec.LookPath(name)
	if err != nil {
		st := Warn
		detail := fmt.Sprintf("%s не найден в PATH (необязателен)", name)
		if required {
			st = Fail
			detail = fmt.Sprintf("%s не найден в PATH — установите его", name)
		}
		return Check{Name: name, Status: st, Detail: detail}
	}
	return Check{Name: name, Status: OK, Detail: path}
}

func permissionCheck() Check {
	if os.Geteuid() == 0 {
		return Check{Name: "права", Status: OK, Detail: "запущено от root"}
	}
	// Без root захват возможен только при наличии CAP_NET_RAW/CAP_NET_ADMIN
	// у tcpdump/dumpcap; мы не можем достоверно проверить capabilities без
	// дополнительных утилит, поэтому предупреждаем.
	return Check{Name: "права", Status: Warn, Detail: "не root — захват может не сработать без CAP_NET_RAW у tcpdump/dumpcap"}
}

func diskSpaceCheck(path string) Check {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return Check{Name: "свободное место", Status: Warn, Detail: "не удалось проверить: " + err.Error()}
	}
	freeBytes := stat.Bavail * uint64(stat.Bsize)
	freeMB := freeBytes / (1024 * 1024)
	if freeMB < 200 {
		return Check{Name: "свободное место", Status: Fail, Detail: fmt.Sprintf("всего %d MB свободно — мало для захвата", freeMB)}
	}
	if freeMB < 1024 {
		return Check{Name: "свободное место", Status: Warn, Detail: fmt.Sprintf("%d MB свободно", freeMB)}
	}
	return Check{Name: "свободное место", Status: OK, Detail: fmt.Sprintf("%d MB свободно", freeMB)}
}

func interfacesCheck() Check {
	names, err := sysinfo.AvailableInterfaceNames()
	if err != nil {
		return Check{Name: "интерфейсы", Status: Fail, Detail: "не удалось получить список: " + err.Error()}
	}
	if len(names) == 0 {
		return Check{Name: "интерфейсы", Status: Fail, Detail: "интерфейсы не найдены"}
	}
	return Check{Name: "интерфейсы", Status: OK, Detail: fmt.Sprintf("%v", names)}
}

// AllOK возвращает true, если нет проваленных проверок (Warn допустим).
func (r Report) AllOK() bool {
	for _, c := range r.Checks {
		if c.Status == Fail {
			return false
		}
	}
	return true
}
