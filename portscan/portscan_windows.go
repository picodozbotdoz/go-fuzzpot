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

// getUsedPortsWindows uses netstat to find TCP LISTEN ports on Windows.
func getUsedPortsWindows() map[int]bool {
        used := make(map[int]bool)

        out, err := exec.Command("netstat", "-an", "-p", "tcp").Output()
        if err != nil {
                // Try without -p flag (older Windows)
                out, err = exec.Command("netstat", "-an").Output()
                if err != nil {
                        return used
                }
        }

        sc := bufio.NewScanner(strings.NewReader(string(out)))
        for sc.Scan() {
                line := strings.TrimSpace(sc.Text())
                fields := strings.Fields(line)
                if len(fields) < 2 {
                        continue
                }
                // Check for LISTENING state
                isListening := false
                if len(fields) >= 4 {
                        state := strings.ToUpper(fields[3])
                        if state == "LISTENING" {
                                isListening = true
                        }
                }
                if !isListening {
                        continue
                }
                // Local address field: 0.0.0.0:80 or [::]:80
                localAddr := fields[1]
                if port := parseWindowsAddr(localAddr); port > 0 {
                        used[port] = true
                }
        }

        return used
}

func parseWindowsAddr(addr string) int {
        // Handle [::]:80 format
        if strings.HasPrefix(addr, "[") {
                if idx := strings.LastIndex(addr, "]:"); idx >= 0 {
                        p, err := strconv.Atoi(addr[idx+2:])
                        if err == nil && p > 0 {
                                return p
                        }
                }
                return 0
        }
        // Handle 0.0.0.0:80 format
        if idx := strings.LastIndex(addr, ":"); idx >= 0 {
                p, err := strconv.Atoi(addr[idx+1:])
                if err == nil && p > 0 {
                        return p
                }
        }
        return 0
}

// EphemeralRange returns sensible defaults for Windows.
// Windows dynamic port range is typically 49152-65535 (Vista+)
// or 1025-5000 (XP/2003).
func EphemeralRange() (int, int, error) {
        // Try to read via netsh
        out, err := exec.Command("netsh", "int", "ipv4", "show", "dynamicport", "tcp").Output()
        if err == nil {
                sc := bufio.NewScanner(strings.NewReader(string(out)))
                for sc.Scan() {
                        line := strings.TrimSpace(sc.Text())
                        if strings.Contains(line, "Start Port") {
                                if p, err := parseNetshValue(line); err == nil {
                                        return p, 65535, nil
                                }
                        }
                }
        }
        // Default Windows Vista+
        return 49152, 65535, nil
}

func parseNetshValue(line string) (int, error) {
        fields := strings.Fields(line)
        if len(fields) >= 3 {
                return strconv.Atoi(fields[2])
        }
        return 0, strconv.ErrSyntax
}
