// Package doctorx реализует проверки окружения перед захватом трафика,
// а также опциональную автоустановку недостающих системных пакетов.
package doctorx

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
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
	// Package — имя apt-пакета, устраняющего проблему (пусто, если
	// проверка не про отсутствующий бинарник — например, права или диск).
	Package string `json:"package,omitempty"`
}

// Report — сводный отчёт doctor.
type Report struct {
	Checks []Check `json:"checks"`
}

// Run выполняет все проверки окружения.
func Run() Report {
	var r Report

	r.Checks = append(r.Checks, binCheck("tcpdump", true, "tcpdump"))
	r.Checks = append(r.Checks, binCheck("dumpcap", false, "tshark"))
	r.Checks = append(r.Checks, binCheck("tshark", true, "tshark"))
	r.Checks = append(r.Checks, binCheck("capinfos", false, "tshark"))
	r.Checks = append(r.Checks, binCheck("mergecap", false, "tshark"))
	r.Checks = append(r.Checks, binCheck("zstd", false, "zstd"))
	r.Checks = append(r.Checks, binCheck("wkhtmltopdf", false, "wkhtmltopdf"))
	r.Checks = append(r.Checks, binCheck("iptables", false, "iptables"))
	r.Checks = append(r.Checks, binCheck("nft", false, "nftables"))
	r.Checks = append(r.Checks, binCheck("conntrack", false, "conntrack"))

	r.Checks = append(r.Checks, permissionCheck())
	r.Checks = append(r.Checks, diskSpaceCheck("."))
	r.Checks = append(r.Checks, interfacesCheck())

	return r
}

func binCheck(name string, required bool, pkg string) Check {
	path, err := exec.LookPath(name)
	if err != nil {
		st := Warn
		detail := fmt.Sprintf("%s не найден в PATH (необязателен, пакет: %s)", name, pkg)
		if required {
			st = Fail
			detail = fmt.Sprintf("%s не найден в PATH — установите пакет %s", name, pkg)
		}
		return Check{Name: name, Status: st, Detail: detail, Package: pkg}
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

// MissingPackages возвращает отсортированный список уникальных apt-пакетов,
// закрывающих все непройденные (Fail и Warn) проверки бинарников.
func (r Report) MissingPackages() []string {
	set := map[string]bool{}
	for _, c := range r.Checks {
		if c.Status != OK && c.Package != "" {
			set[c.Package] = true
		}
	}
	pkgs := make([]string, 0, len(set))
	for p := range set {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	return pkgs
}

// PackageManager — определяет доступный на хосте пакетный менеджер.
// Автоустановка (Install) сейчас поддерживает только apt; для остальных
// возвращается имя менеджера, чтобы ManualInstallHint могла подсказать
// правильную команду вручную.
func PackageManager() string {
	for _, pm := range []string{"apt-get", "dnf", "yum", "pacman", "apk", "brew"} {
		if _, err := exec.LookPath(pm); err == nil {
			return pm
		}
	}
	return ""
}

// ManualInstallHint формирует команду для ручной установки под
// определённый на хосте пакетный менеджер (или общую подсказку, если
// определить не удалось).
func ManualInstallHint(packages []string) string {
	if len(packages) == 0 {
		return ""
	}
	list := strings.Join(packages, " ")
	switch PackageManager() {
	case "apt-get":
		return "sudo apt-get update && sudo apt-get install -y " + list
	case "dnf":
		return "sudo dnf install -y " + list
	case "yum":
		return "sudo yum install -y " + list
	case "pacman":
		return "sudo pacman -S --noconfirm " + list
	case "apk":
		return "sudo apk add " + list
	case "brew":
		return "brew install " + list
	default:
		return "установите вручную через пакетный менеджер вашего дистрибутива: " + list
	}
}

// Install пытается автоматически установить недостающие пакеты.
// Поддерживается только apt (Ubuntu/Debian) — на остальных системах
// возвращается ошибка с рекомендацией использовать ManualInstallHint.
// Требует root. Вывод apt транслируется в переданный io.Writer построчно
// через onOutput (может быть nil).
func Install(packages []string, onOutput func(line string)) error {
	if len(packages) == 0 {
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("автоустановка требует root (запустите с sudo)")
	}
	pm := PackageManager()
	if pm != "apt-get" {
		hint := ManualInstallHint(packages)
		if pm == "" {
			return fmt.Errorf("не удалось определить пакетный менеджер; установите вручную: %s", strings.Join(packages, " "))
		}
		return fmt.Errorf("автоустановка пока поддерживает только apt (обнаружен %s); установите вручную:\n  %s", pm, hint)
	}

	// apt-get update может завершиться с ошибкой из-за одного недоступного
	// стороннего репозитория (например, добавленного вручную PPA), даже
	// если основные репозитории Ubuntu/Debian обновились нормально. Не
	// прерываемся на этом — пробуем install; если нужных пакетов всё
	// равно нет, install сам вернёт понятную ошибку.
	if err := runStreaming(onOutput, "apt-get", "update", "-y"); err != nil {
		if onOutput != nil {
			onOutput(fmt.Sprintf("предупреждение: apt-get update завершился с ошибкой (%v) — пробую установить пакеты всё равно", err))
		}
	}

	args := append([]string{"install", "-y"}, packages...)
	if err := runStreaming(onOutput, "apt-get", args...); err != nil {
		return fmt.Errorf("apt-get install: %w", err)
	}
	return nil
}

func runStreaming(onOutput func(string), name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout // apt пишет прогресс в stderr — сливаем в один поток
	if err := cmd.Start(); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	for {
		n, rerr := stdout.Read(buf)
		if n > 0 && onOutput != nil {
			for _, line := range strings.Split(strings.TrimRight(string(buf[:n]), "\n"), "\n") {
				if line != "" {
					onOutput(line)
				}
			}
		}
		if rerr != nil {
			break
		}
	}
	return cmd.Wait()
}
