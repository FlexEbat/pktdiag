// Package explainx реализует Explain Engine: объясняет сетевые
// терминов и метрик простым языком с указанием причин и рекомендаций.
package explainx

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed data/explain.json
var dataFS embed.FS

// Entry хранит одну статью базы знаний.
type Entry struct {
	ID              string   `json:"id"`
	Aliases         []string `json:"aliases"`
	Title           string   `json:"title"`
	Good            string   `json:"good"`
	Warning         string   `json:"warning"`
	Critical        string   `json:"critical"`
	What            string   `json:"what"`
	Causes          []string `json:"causes"`
	Recommendations []string `json:"recommendations"`
}

var (
	entries []Entry
	index   map[string]*Entry
)

func init() {
	b, err := dataFS.ReadFile("data/explain.json")
	if err != nil {
		panic("explainx: не удалось прочитать встроенную базу знаний: " + err.Error())
	}
	if err := json.Unmarshal(b, &entries); err != nil {
		panic("explainx: некорректный explain.json: " + err.Error())
	}
	index = make(map[string]*Entry)
	for i := range entries {
		e := &entries[i]
		index[normalize(e.ID)] = e
		for _, a := range e.Aliases {
			index[normalize(a)] = e
		}
	}
}

func normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "-", "_")
	return s
}

// Lookup ищет статью по термину (id, алиасу, с учётом регистра и пробелов/дефисов).
func Lookup(term string) (*Entry, bool) {
	e, ok := index[normalize(term)]
	return e, ok
}

// All возвращает список ID всех известных терминов, для help и автодополнения.
func All() []string {
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, e.ID)
	}
	sort.Strings(ids)
	return ids
}

// Format форматирует статью для вывода в терминал.
func Format(e *Entry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", e.Title)
	fmt.Fprintf(&b, "Норма:      %s\n", orDash(e.Good))
	fmt.Fprintf(&b, "Warning:    %s\n", orDash(e.Warning))
	fmt.Fprintf(&b, "Critical:   %s\n\n", orDash(e.Critical))
	fmt.Fprintf(&b, "Что это означает\n%s\n", e.What)
	if len(e.Causes) > 0 {
		fmt.Fprintf(&b, "\nВозможные причины\n")
		for _, c := range e.Causes {
			fmt.Fprintf(&b, "  • %s\n", c)
		}
	}
	if len(e.Recommendations) > 0 {
		fmt.Fprintf(&b, "\nРекомендации\n")
		for _, r := range e.Recommendations {
			fmt.Fprintf(&b, "  • %s\n", r)
		}
	}
	return b.String()
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}
