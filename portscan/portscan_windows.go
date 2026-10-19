//go:build windows

package portscan

import (
	"bufio"
	"os/exec"
	"strconv"
	"strings"
)

func init() {
	GetUsedPorts = getUsedPortsWindows
}

// getUsedPortsWindows uses netstat to find listening TCP ports on Windows.
//
// D-20: `-p tcp` lists IPv4 sockets only, so an IPv6-only listener was
// missed; both protocols are queried now.
func getUsedPortsWindows() map[int]bool {
	used := make(map[int]bool)
	queried := false
	for _, proto := range []string{"tcp", "tcpv6"} {
		out, err := exec.Command("netstat", "-an", "-p", proto).Output()
		if err != nil {
			continue
		}
		queried = true
		parseNetstatListening(string(out), used)
	}
	if !queried {
		// Older Windows without -p: one combined listing.
		if out, err := exec.Command("netstat", "-an").Output(); err == nil {
			parseNetstatListening(string(out), used)
		}
	}
	return used
}

// parseNetstatListening adds the local port of every listening TCP socket
// in `netstat -an` output to used.
//
// D-20: a listening row is recognised by its wildcard foreign address
// ("0.0.0.0:0", "[::]:0") as well as by the state column, because Windows
// localises that column ("LISTENING", "ABHÖREN", ...).
func parseNetstatListening(out string, used map[int]bool) {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || !strings.EqualFold(fields[0], "TCP") {
			continue
		}
		foreign := fields[2]
		if foreign != "0.0.0.0:0" && foreign != "[::]:0" && !strings.EqualFold(fields[3], "LISTENING") {
			continue
		}
		if port := parseAddrPort(fields[1]); port > 0 {
			used[port] = true
		}
	}
}

// EphemeralRange returns the TCP dynamic port range reported by netsh, or
// the Vista+ default 49152-65535 when it cannot be read.
func EphemeralRange() (int, int, error) {
	out, err := exec.Command("netsh", "int", "ipv4", "show", "dynamicport", "tcp").Output()
	if err == nil {
		if lo, hi, ok := parseDynamicPortRange(string(out)); ok {
			return lo, hi, nil
		}
	}
	return 49152, 65535, nil
}

// parseDynamicPortRange reads netsh's "Start Port : N" and
// "Number of Ports : M" lines and returns N and N+M-1.
//
// D-20: the end used to be hardcoded to 65535, which is only right for the
// default range. Values are taken positionally (the first two "label : number"
// lines) because the labels are localised.
func parseDynamicPortRange(out string) (int, int, bool) {
	var nums []int
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() && len(nums) < 2 {
		line := sc.Text()
		i := strings.LastIndex(line, ":")
		if i < 0 {
			continue
		}
		if v, err := strconv.Atoi(strings.TrimSpace(line[i+1:])); err == nil {
			nums = append(nums, v)
		}
	}
	if len(nums) < 2 {
		return 0, 0, false
	}
	lo, count := nums[0], nums[1]
	hi := lo + count - 1
	if lo < 1 || count < 1 || hi > 65535 {
		return 0, 0, false
	}
	return lo, hi, true
}
