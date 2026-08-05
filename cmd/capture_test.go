package cmd

import "testing"

func TestParseSize(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"500MB", 500_000_000, false},
		{"2GB", 2_000_000_000, false},
		{"100K", 100_000, false},
		{"1.5G", 1_500_000_000, false},
		{"1000", 1000, false},
		{"abc", 0, true},
		{"GB", 0, true},
	}
	for _, c := range cases {
		got, err := parseSize(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseSize(%q): ожидалась ошибка, получено %d без ошибки", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSize(%q): неожиданная ошибка %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseSize(%q) = %d, ожидалось %d", c.in, got, c.want)
		}
	}
}
