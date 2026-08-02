// Package archive упаковывает каталог с результатами захвата в tar.zst,
// используя системные tar и zstd (см. UC-07 "Production Bundle" в ТЗ).
package archive

import (
	"fmt"
	"os/exec"
)

// CreateTarZst упаковывает содержимое srcDir в архив destTarZst.
// Требует наличия tar с поддержкой --zstd (GNU tar) и бинаря zstd в PATH.
func CreateTarZst(srcDir, destTarZst string) error {
	if _, err := exec.LookPath("zstd"); err != nil {
		return fmt.Errorf("zstd не найден в PATH: %w", err)
	}
	cmd := exec.Command("tar", "--zstd", "-cf", destTarZst, "-C", srcDir, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tar --zstd: %w\n%s", err, string(out))
	}
	return nil
}
