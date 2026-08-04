// Package doctorx проверяет окружение перед захватом трафика и
// умеет автоматически ставить недостающие системные пакеты.
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

// Status хранит результат одной проверки.
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

// Check хранит одну строку отчёта doctor.
type Check struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
	// Package хранит имя apt-пакета, который устраняет проблему.
	// Пусто, если проверка касается прав или диска, а не бинарника.
	Package string `json:"package,omitempty"`
}

// Report хранит сводный отчёт doctor.
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
			detail = fmt.Sprintf("%s не найден в PATH, установите пакет %s", name, pkg)
		}
		return Check{Name: name, Status: st, Detail: detail, Package: pkg}
	}
	return Check{Name: name, Status: OK, Detail: path}
}

func permissionCheck() Check {
	if os.Geteuid() == 0 {
		return Check{Name: "права", Status: OK, Detail: "запущено от root"}
	}
	// Без root capabilities CAP_NET_RAW/CAP_NET_ADMIN проверить нельзя без
	// дополнительных утилит, поэтому предупреждаем вместо точного вердикта.
	return Check{Name: "права", Status: Warn, Detail: "захват без root требует CAP_NET_RAW у tcpdump/dumpcap"}
}

func diskSpaceCheck(path string) Check {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return Check{Name: "свободное место", Status: Warn, Detail: "не удалось проверить: " + err.Error()}
	}
	freeBytes := stat.Bavail * uint64(stat.Bsize)
	freeMB := freeBytes / (1024 * 1024)
	if freeMB < 200 {
		return Check{Name: "свободное место", Status: Fail, Detail: fmt.Sprintf("свободно %d MB, недостаточно для захвата", freeMB)}
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

// AllOK возвращает true, если ни одна проверка не завершилась Fail (Warn допустим).
func (r Report) AllOK() bool {
	for _, c := range r.Checks {
		if c.Status == Fail {
			return false
		}
	}
	return true
}

// MissingPackages возвращает отсортированный список уникальных apt-пакетов
// для всех непройденных проверок бинарников (Fail и Warn).
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

// PackageManager определяет доступный на хосте пакетный менеджер.
// Install сейчас умеет ставить пакеты только через apt; для остальных
// менеджеров ManualInstallHint строит команду для ручного запуска.
func PackageManager() string {
	for _, pm := range []string{"apt-get", "dnf", "yum", "pacman", "apk", "brew"} {
		if _, err := exec.LookPath(pm); err == nil {
			return pm
		}
	}
	return ""
}

// ManualInstallHint строит команду для ручной установки под обнаруженный
// на хосте пакетный менеджер. Если определить менеджер не удалось,
// возвращает общую подсказку.
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

// Install ставит недостающие пакеты автоматически. Поддерживает только
// apt (Ubuntu/Debian) и требует root; на других системах возвращает
// ошибку с рекомендацией использовать ManualInstallHint. Вывод apt
// передаётся построчно через onOutput (может быть nil).
func Install(packages []string, onOutput func(line string)) error {
	if len(packages) == 0 {
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("автоустановка требует root, запустите с sudo")
	}
	pm := PackageManager()
	if pm != "apt-get" {
		hint := ManualInstallHint(packages)
		if pm == "" {
			return fmt.Errorf("не удалось определить пакетный менеджер, установите вручную: %s", strings.Join(packages, " "))
		}
		return fmt.Errorf("автоустановка пока поддерживает только apt, обнаружен %s, установите вручную:\n  %s", pm, hint)
	}

	// Сторонний репозиторий (например, ручной PPA) может быть недоступен
	// и провалить весь apt-get update, даже когда основные репозитории
	// Ubuntu/Debian обновились нормально. Install продолжает установку:
	// если нужного пакета всё равно нет, apt-get install вернёт свою ошибку.
	if err := runStreaming(onOutput, "apt-get", "update", "-y"); err != nil {
		if onOutput != nil {
			onOutput(fmt.Sprintf("предупреждение: apt-get update завершился с ошибкой (%v), пробую установить пакеты всё равно", err))
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
	// apt пишет прогресс установки в stderr, оба потока идут в один Reader.
	cmd.Stderr = cmd.Stdout
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
