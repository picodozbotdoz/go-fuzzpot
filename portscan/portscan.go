package portscan

import "sync"

// IsEphemeral checks if a port falls within the ephemeral range.
func IsEphemeral(port int, ephLo, ephHi int) bool {
        return port >= ephLo && port <= ephHi
}

// GetUsedPorts is a function variable that returns the set of currently used TCP ports.
// It is assigned by platform-specific init() functions and can be overridden in tests.
var GetUsedPorts func() map[int]bool

// PortManager manages the set of honeypot listener ports,
// handling conflict detection and dynamic refresh.
type PortManager struct {
        mu            sync.RWMutex
        listenPorts   map[int]struct{} // ports we're currently listening on
        excludePorts  map[int]struct{} // user-configured excludes
        ephLo, ephHi  int              // ephemeral range
}

func NewPortManager(exclude []int) *PortManager {
        pm := &PortManager{
                listenPorts:  make(map[int]struct{}),
                excludePorts: make(map[int]struct{}),
        }
        for _, p := range exclude {
                pm.excludePorts[p] = struct{}{}
        }
        pm.ephLo, pm.ephHi, _ = EphemeralRange()
        return pm
}

// TargetPorts returns the ports we should listen on:
// union of all configured ranges, minus used ports, minus excludes, minus ephemeral.
func (pm *PortManager) TargetPorts(ranges [][2]int) []int {
        used := GetUsedPorts()
        pm.mu.Lock()
        defer pm.mu.Unlock()

        result := make(map[int]struct{})
        for _, r := range ranges {
                for p := r[0]; p <= r[1]; p++ {
                        if used[p] {
                                continue
                        }
                        if _, ok := pm.excludePorts[p]; ok {
                                continue
                        }
                        if IsEphemeral(p, pm.ephLo, pm.ephHi) {
                                continue
                        }
                        result[p] = struct{}{}
                }
        }

        ports := make([]int, 0, len(result))
        for p := range result {
                ports = append(ports, p)
        }
        return ports
}

// SetListening marks a port as being listened on.
func (pm *PortManager) SetListening(port int) {
        pm.mu.Lock()
        defer pm.mu.Unlock()
        pm.listenPorts[port] = struct{}{}
}

// ClearListening removes a port from the listened set.
func (pm *PortManager) ClearListening(port int) {
        pm.mu.Lock()
        defer pm.mu.Unlock()
        delete(pm.listenPorts, port)
}

// ListeningCount returns the number of ports currently being listened on.
func (pm *PortManager) ListeningCount() int {
        pm.mu.RLock()
        defer pm.mu.RUnlock()
        return len(pm.listenPorts)
}

// DetectConflicts checks if any of our listen ports have been claimed
// by a new system service. Returns ports that should be released.
func (pm *PortManager) DetectConflicts() []int {
        used := GetUsedPorts()
        pm.mu.RLock()
        defer pm.mu.RUnlock()

        var conflicts []int
        for p := range pm.listenPorts {
                if used[p] {
                        conflicts = append(conflicts, p)
                }
        }
        return conflicts
}

// RefreshEphemeralRange re-reads the ephemeral range from the platform.
func (pm *PortManager) RefreshEphemeralRange() {
        pm.mu.Lock()
        defer pm.mu.Unlock()
        pm.ephLo, pm.ephHi, _ = EphemeralRange()
}
