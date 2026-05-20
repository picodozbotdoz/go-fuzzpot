//go:build !linux && !windows && !freebsd

package portscan

import (
        "fmt"
        "net"
        "sync"
)

// GetUsedPorts uses a net.Listen probe as cross-platform fallback.
// It briefly attempts to bind each port to check if it's in use.
// This is slower than platform-specific methods but works everywhere.
func GetUsedPorts() map[int]bool {
        return probeUsedPorts(probeDefaultRanges())
}

// EphemeralRange returns a sensible default for unknown platforms.
func EphemeralRange() (int, int, error) {
        return 32768, 60999, nil
}

// probeDefaultRanges returns the port ranges to probe on fallback platforms.
func probeDefaultRanges() [][2]int {
        return [][2]int{
                {1, 1024},
                {2000, 10000},
                {32768, 61000},
        }
}

// probeUsedPorts tries to bind each port to detect if it's in use.
// Uses a bounded worker pool to prevent FD exhaustion from spawning
// thousands of simultaneous goroutines.
func probeUsedPorts(ranges [][2]int) map[int]bool {
        used := make(map[int]bool)
        var mu sync.Mutex

        // Count total ports to probe
        total := 0
        for _, r := range ranges {
                total += r[1] - r[0] + 1
        }

        // Use bounded worker pool to limit concurrent binds
        workers := 100
        if total < workers {
                workers = total
        }

        type result struct {
                port int
                inUse bool
        }
        results := make(chan result, workers)

        // Generate port list
        ports := make([]int, 0, total)
        for _, r := range ranges {
                for p := r[0]; p <= r[1]; p++ {
                        ports = append(ports, p)
                }
        }

        // Feed ports to workers
        portCh := make(chan int, workers)
        go func() {
                for _, p := range ports {
                        portCh <- p
                }
                close(portCh)
        }()

        // Launch workers
        var wg sync.WaitGroup
        for i := 0; i < workers; i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        for port := range portCh {
                                ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
                                if err != nil {
                                        results <- result{port: port, inUse: true}
                                } else {
                                        ln.Close()
                                        results <- result{port: port, inUse: false}
                                }
                        }
                }()
        }

        // Close results channel when all workers done
        go func() {
                wg.Wait()
                close(results)
        }()

        // Collect results
        for r := range results {
                if r.inUse {
                        mu.Lock()
                        used[r.port] = true
                        mu.Unlock()
                }
        }

        return used
}
