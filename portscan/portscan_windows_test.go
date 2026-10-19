//go:build windows

package portscan

import (
	"net"
	"testing"
)

// D-20: the range end is start + count - 1. Returning 65535 was only right
// for the default 49152/16384. The parser reads values, not English labels.
func TestParseDynamicPortRange(t *testing.T) {
	for _, tc := range []struct {
		name   string
		out    string
		lo, hi int
		ok     bool
	}{
		{"default", "Protocol tcp Dynamic Port Range\r\n---------------------------------\r\nStart Port      : 49152\r\nNumber of Ports : 16384\r\n", 49152, 65535, true},
		{"custom range", "Start Port      : 10000\r\nNumber of Ports : 1000\r\n", 10000, 10999, true},
		{"localised labels", "Startport      : 50000\r\nAnzahl der Ports : 100\r\n", 50000, 50099, true},
		{"start only", "Start Port      : 49152\r\n", 0, 0, false},
		{"past 65535", "Start Port : 60000\r\nNumber of Ports : 10000\r\n", 0, 0, false},
		{"garbage", "garbage", 0, 0, false},
	} {
		lo, hi, ok := parseDynamicPortRange(tc.out)
		if lo != tc.lo || hi != tc.hi || ok != tc.ok {
			t.Errorf("%s: parseDynamicPortRange = (%d, %d, %v), want (%d, %d, %v)", tc.name, lo, hi, ok, tc.lo, tc.hi, tc.ok)
		}
	}
}

// D-20: listening rows are found by their wildcard foreign address, so a
// non-English state column ("ABHÖREN") still counts. IPv6 rows count too.
func TestParseNetstatListening(t *testing.T) {
	out := "\r\nActive Connections\r\n\r\n  Proto  Local Address          Foreign Address        State\r\n" +
		"  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING\r\n" +
		"  TCP    0.0.0.0:3389           0.0.0.0:0              ABHÖREN\r\n" +
		"  TCP    [::]:445               [::]:0                 LISTENING\r\n" +
		"  TCP    10.0.0.5:50123         93.184.216.34:443      ESTABLISHED\r\n" +
		"  UDP    0.0.0.0:5353           *:*\r\n"
	used := map[int]bool{}
	parseNetstatListening(out, used)
	want := map[int]bool{135: true, 3389: true, 445: true}
	if len(used) != len(want) {
		t.Fatalf("parseNetstatListening = %v, want %v", used, want)
	}
	for p := range want {
		if !used[p] {
			t.Errorf("port %d missing from %v", p, used)
		}
	}
}

func TestGetUsedPortsSeesIPv4AndIPv6Listeners(t *testing.T) {
	ln4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln4.Close()
	ln6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this host: %v", err)
	}
	defer ln6.Close()

	used := GetUsedPorts()
	for _, ln := range []net.Listener{ln4, ln6} {
		if p := ln.Addr().(*net.TCPAddr).Port; !used[p] {
			t.Errorf("listener on %s not reported as used", ln.Addr())
		}
	}
}

func TestEphemeralRangeMatchesThisHost(t *testing.T) {
	lo, hi, err := EphemeralRange()
	if err != nil || lo < 1 || hi > 65535 || lo > hi {
		t.Fatalf("EphemeralRange() = %d, %d, %v", lo, hi, err)
	}
}
