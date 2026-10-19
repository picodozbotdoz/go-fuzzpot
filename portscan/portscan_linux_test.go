//go:build linux

package portscan

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// The /proc parsers were the only build-tag variant with zero coverage: they
// only compile on Linux, so the Windows dev host could never exercise them and
// the CI race lane never ran them either. These tests run on the Linux lane.

func TestParseHexPort(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want int
		fail bool
	}{
		{"ipv4 listen", "00000000:1F90", 8080, false},
		{"ipv4 loopback", "0100007F:0050", 80, false},
		{"ipv6 listen", "00000000000000000000000000000000:22B8", 8888, false},
		{"port zero", "00000000:0000", 0, false},
		{"missing colon", "000000001F90", 0, true},
		{"non-hex port", "00000000:ZZZZ", 0, true},
		{"empty", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHexPort(tt.addr)
			if tt.fail {
				if err == nil {
					t.Fatalf("parseHexPort(%q) = %d, want an error", tt.addr, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseHexPort(%q): %v", tt.addr, err)
			}
			if got != tt.want {
				t.Errorf("parseHexPort(%q) = %d, want %d", tt.addr, got, tt.want)
			}
		})
	}
}

// A slice of a real /proc/net/tcp: header line, one LISTEN socket, one
// ESTABLISHED socket, a tcp6 entry and a malformed line.
const procNetTCPFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0050 0100007F:D2F1 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 20 4 30 10 -1
   2: 00000000000000000000000000000000:22B8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12347 1 0000000000000000 100 0 0 10 0
   3: garbage line
   4: 00000000:ABCD 00000000:0000 06 00000000:00000000 00:00000000 00000000  1000        0 12348 1 0000000000000000 100 0 0 10 0
`

func TestMergeFile_OnlyListenSockets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tcp")
	if err := os.WriteFile(path, []byte(procNetTCPFixture), 0o600); err != nil {
		t.Fatal(err)
	}

	used := map[int]bool{}
	mergeFile(used, path)

	// 8080 (0x1F90) and 8888 (0x22B8) are in state 0A.
	if !used[8080] {
		t.Error("port 8080 (state 0A) was not collected")
	}
	if !used[8888] {
		t.Error("port 8888 (state 0A, tcp6 line) was not collected")
	}
	// 80 is ESTABLISHED (01), 43981 (0xABCD) is TIME_WAIT (06).
	if used[80] {
		t.Error("port 80 is ESTABLISHED, not LISTEN — it must not be treated as used")
	}
	if used[43981] {
		t.Error("port 43981 is TIME_WAIT, not LISTEN — it must not be treated as used")
	}
}

func TestMergeFile_MissingFileIsNotFatal(t *testing.T) {
	used := map[int]bool{4242: true}
	mergeFile(used, filepath.Join(t.TempDir(), "does-not-exist"))

	if len(used) != 1 || !used[4242] {
		t.Fatalf("a missing /proc file must leave the map untouched, got %v", used)
	}
}

// getUsedPortsLinux must see a listener this process holds: that is the whole
// point of the /proc read, and it is what makes TargetPorts skip ports already
// in use on the host.
func TestGetUsedPortsLinux_SeesOwnListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	used := getUsedPortsLinux()

	if !used[port] {
		t.Fatalf("getUsedPortsLinux() did not report our own listener on port %d", port)
	}
}
