// Package yamlcfg реализует чтение конфигурации pktdiag.yaml.
//
// Это НЕ полноценный YAML-парсер: сеть в среде сборки блокирует все
// внешние Go-модули (см. README — попытка подключить bubbletea упёрлась
// в недоступность golang.org/x/*), поэтому вместо стороннего пакета
// (gopkg.in/yaml.v3 и т.п.) реализован узкий парсер под конкретную
// структуру конфига из ТЗ:
//
//	capture:
//	  iface: eth0
//	  duration: 60s
//	report:
//	  format: html,json
//	analysis:
//	  dns: true
//
// Поддерживается только два уровня вложенности, простые скаляры
// (строки/числа/bool), однострочные комментарии через "#" и пустые строки.
// Списки, многострочные строки, якоря и т.п. — не поддерживаются.
package yamlcfg

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config — секции, которые понимает pktdiag.yaml.
type Config struct {
	Sections map[string]map[string]string
}

// Load читает и разбирает файл конфигурации. Если файла нет — возвращает
// пустой Config и nil error (конфиг необязателен).
func Load(path string) (Config, error) {
	cfg := Config{Sections: map[string]map[string]string{}}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("не удалось открыть %s: %w", path, err)
	}
	defer f.Close()

	var currentSection string
	lineNo := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lineNo++
		raw := sc.Text()

		line := stripComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " "))
		trimmed := strings.TrimSpace(line)

		if indent == 0 {
			// Секция верхнего уровня: "capture:" (значение после ":" игнорируется)
			name := strings.TrimSuffix(trimmed, ":")
			name = strings.TrimSpace(strings.SplitN(name, ":", 2)[0])
			currentSection = name
			if _, ok := cfg.Sections[currentSection]; !ok {
				cfg.Sections[currentSection] = map[string]string{}
			}
			continue
		}

		if currentSection == "" {
			return cfg, fmt.Errorf("%s:%d: значение вне секции: %q", path, lineNo, trimmed)
		}

		key, value, err := splitKV(trimmed)
		if err != nil {
			return cfg, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		cfg.Sections[currentSection][key] = value
	}
	if err := sc.Err(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func stripComment(line string) string {
	inQuotes := false
	for i, r := range line {
		switch r {
		case '"', '\'':
			inQuotes = !inQuotes
		case '#':
			if !inQuotes {
				return line[:i]
			}
		}
	}
	return line
}

func splitKV(s string) (key, value string, err error) {
	idx := strings.IndexByte(s, ':')
	if idx < 0 {
		return "", "", fmt.Errorf("ожидался 'ключ: значение', получено %q", s)
	}
	key = strings.TrimSpace(s[:idx])
	value = strings.TrimSpace(s[idx+1:])
	value = unquote(value)
	if key == "" {
		return "", "", fmt.Errorf("пустой ключ в %q", s)
	}
	return key, value, nil
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// Get возвращает строковое значение section.key или def, если его нет.
func (c Config) Get(section, key, def string) string {
	if s, ok := c.Sections[section]; ok {
		if v, ok := s[key]; ok && v != "" {
			return v
		}
	}
	return def
}

// GetInt — то же, что Get, но с разбором в int; при ошибке разбора
// возвращает def.
func (c Config) GetInt(section, key string, def int) int {
	v := c.Get(section, key, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// GetBool — то же, что Get, но с разбором в bool; при ошибке разбора
// возвращает def.
func (c Config) GetBool(section, key string, def bool) bool {
	v := c.Get(section, key, "")
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}
