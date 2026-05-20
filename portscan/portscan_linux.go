//go:build linux

package portscan

import (
        "bufio"
        "bytes"
        "fmt"
        "os"
        "strconv"
        "strings"
)

func init() {
        GetUsedPorts = getUsedPortsLinux
}

// getUsedPortsLinux reads /proc/net/tcp and /proc/net/tcp6 to find all
// TCP ports in LISTEN state (state 0A).
func getUsedPortsLinux() map[int]bool {
        used := make(map[int]bool)
        mergeFile(used, "/proc/net/tcp")
        mergeFile(used, "/proc/net/tcp6")
        return used
}

func mergeFile(used map[int]bool, path string) {
        data, err := os.ReadFile(path)
        if err != nil {
                return
        }
        scanner := bufio.NewScanner(bytes.NewReader(data))
        for scanner.Scan() {
                fields := strings.Fields(scanner.Text())
                if len(fields) < 4 {
                        continue
                }
                if fields[3] != "0A" {
                        continue
                }
                port, err := parseHexPort(fields[1])
                if err != nil {
                        continue
                }
                used[port] = true
        }
}

func parseHexPort(addr string) (int, error) {
        parts := strings.Split(addr, ":")
        if len(parts) != 2 {
                return 0, fmt.Errorf("bad addr format: %s", addr)
        }
        p, err := strconv.ParseInt(parts[1], 16, 32)
        if err != nil {
                return 0, err
        }
        return int(p), nil
}

// EphemeralRange reads /proc/sys/net/ipv4/ip_local_port_range.
func EphemeralRange() (int, int, error) {
        data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
        if err != nil {
                return 32768, 60999, nil
        }
        fields := strings.Fields(strings.TrimSpace(string(data)))
        if len(fields) != 2 {
                return 32768, 60999, nil
        }
        lo, err1 := strconv.Atoi(fields[0])
        hi, err2 := strconv.Atoi(fields[1])
        if err1 != nil || err2 != nil {
                return 32768, 60999, nil
        }
        return lo, hi, nil
}
