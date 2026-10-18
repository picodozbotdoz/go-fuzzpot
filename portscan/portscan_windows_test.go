//go:build windows

package portscan

import "testing"

// R2-G5: netsh prints "Start Port      : 49152" — the value is the last
// token; reading fields[2] grabbed the ":" separator and always failed.
func TestParseNetshValue(t *testing.T) {
	for _, tc := range []struct {
		line string
		want int
		ok   bool
	}{
		{"Start Port      : 49152", 49152, true},
		{"Number of Ports : 16384", 16384, true},
		{"Start Port : 1024", 1024, true},
		{"garbage", 0, false},
		{"", 0, false},
	} {
		got, err := parseNetshValue(tc.line)
		if tc.ok && (err != nil || got != tc.want) {
			t.Errorf("parseNetshValue(%q) = %d, %v; want %d, nil", tc.line, got, err, tc.want)
		}
		if !tc.ok && err == nil {
			t.Errorf("parseNetshValue(%q) = %d; want error", tc.line, got)
		}
	}
}
