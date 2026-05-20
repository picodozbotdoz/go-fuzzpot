//go:build freebsd

package portscan

import (
        "bufio"
        "os/exec"
        "strconv"
        "strings"
)

func init() {
        GetUsedPorts = getUsedPortsFreeBSD
}

// getUsedPortsFreeBSD uses sockstat to find TCP LISTEN ports on FreeBSD.
func getUsedPortsFreeBSD() map[int]bool {
        used := make(map[int]bool)

        // Try sockstat first (faster, FreeBSD-specific)
        if data, err := exec.Command("sockstat", "-4l", "-p", "tcp").Output(); err == nil {
                parseSockstat(data, used)
        } else if data, err := exec.Command("sockstat", "-l").Output(); err == nil {
                parseSockstat(data, used)
        } else {
                // Fallback to netstat
                if data, err := exec.Command("netstat", "-an", "-p", "tcp").Output(); err == nil {
                        parseNetstat(data, used)
                }
        }

        return used
}

func parseSockstat(data []byte, used map[int]bool) {
        sc := bufio.NewScanner(strings.NewReader(string(data)))
        for sc.Scan() {
                fields := strings.Fields(sc.Text())
                if len(fields) < 6 {
                        continue
                }
                // sockstat format: USER COMMAND PID FD PROTO ADDRESS
                addr := fields[5] // e.g. *:80 or 192.168.1.1:80
                if port := parseAddrPort(addr); port > 0 {
                        used[port] = true
                }
        }
}

func parseNetstat(data []byte, used map[int]bool) {
        sc := bufio.NewScanner(strings.NewReader(string(data)))
        for sc.Scan() {
                fields := strings.Fields(sc.Text())
                if len(fields) < 4 {
                        continue
                }
                // netstat format: Proto Recv-Q Send-Q Local Address
                localAddr := fields[3] // e.g. *.80 or 192.168.1.1.80
                if port := parseAddrPort(strings.TrimSuffix(localAddr, ".*")); port > 0 {
                        used[port] = true
                }
        }
}

func parseAddrPort(addr string) int {
        // Handle formats: *:80, 0.0.0.0:80, *.80, 127.0.0.1.80
        if idx := strings.LastIndex(addr, ":"); idx >= 0 {
                p, err := strconv.Atoi(addr[idx+1:])
                if err == nil && p > 0 {
                        return p
                }
        } else if idx := strings.LastIndex(addr, "."); idx >= 0 {
                p, err := strconv.Atoi(addr[idx+1:])
                if err == nil && p > 0 {
                        return p
                }
        }
        return 0
}

// EphemeralRange reads net.inet.ip.portrange.first/last sysctl on FreeBSD.
func EphemeralRange() (int, int, error) {
        lo, err := sysctlInt("net.inet.ip.portrange.first")
        if err != nil {
                return 32768, 60999, nil
        }
        hi, err := sysctlInt("net.inet.ip.portrange.last")
        if err != nil {
                return 32768, 60999, nil
        }
        return lo, hi, nil
}

func sysctlInt(name string) (int, error) {
        data, err := exec.Command("sysctl", "-n", name).Output()
        if err != nil {
                return 0, err
        }
        return strconv.Atoi(strings.TrimSpace(string(data)))
}
