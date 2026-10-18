package portscan

import (
	"sort"
	"strconv"
	"strings"
	"sync"
)

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
	mu           sync.RWMutex
	listenPorts  map[int]struct{} // ports we're currently listening on
	excludePorts map[int]struct{} // user-configured excludes
	lostPorts    map[int]struct{} // listeners that died and could not be rebound
	ephLo, ephHi int              // ephemeral range
}

func NewPortManager(exclude []int) *PortManager {
	pm := &PortManager{
		listenPorts:  make(map[int]struct{}),
		excludePorts: make(map[int]struct{}),
		lostPorts:    make(map[int]struct{}),
	}
	for _, p := range exclude {
		pm.excludePorts[p] = struct{}{}
	}
	pm.ephLo, pm.ephHi, _ = EphemeralRange()
	return pm
}

// TargetPorts returns the ports we should listen on:
// union of all configured ranges, minus used ports, minus excludes, minus ephemeral.
// FIX: Acquire lock BEFORE reading used ports to prevent TOCTOU race.
func (pm *PortManager) TargetPorts(ranges [][2]int) []int {
	// Acquire lock BEFORE reading used ports to ensure consistency
	pm.mu.Lock()

	// Snapshot used ports while holding lock
	used := GetUsedPorts()

	// Also snapshot ephemeral range
	ephLo, ephHi := pm.ephLo, pm.ephHi

	result := make(map[int]struct{})
	for _, r := range ranges {
		for p := r[0]; p <= r[1]; p++ {
			if used[p] {
				continue
			}
			if _, ok := pm.excludePorts[p]; ok {
				continue
			}
			if IsEphemeral(p, ephLo, ephHi) {
				continue
			}
			result[p] = struct{}{}
		}
	}

	ports := make([]int, 0, len(result))
	for p := range result {
		ports = append(ports, p)
	}

	pm.mu.Unlock() // Unlock after all reads complete
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

// MarkLost records that a listener we had bound stopped accepting and could
// not be rebound. The port leaves the listened set so a later successful
// rebind re-adds it.
func (pm *PortManager) MarkLost(port int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.listenPorts, port)
	pm.lostPorts[port] = struct{}{}
}

// DetectConflicts returns ports whose listener died since the last call, then
// clears them.
//
// The previous implementation compared our listen set against GetUsedPorts(),
// a system-wide socket table that includes our own listeners. Every bound port
// was therefore reported as a conflict on every refresh tick — thousands of
// ports per minute into security.log, rolling the audit trail away in hours.
// A port we hold cannot be claimed by another process, so the only meaningful
// signal is that our own listener stopped.
func (pm *PortManager) DetectConflicts() []int {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if len(pm.lostPorts) == 0 {
		return nil
	}

	ports := make([]int, 0, len(pm.lostPorts))
	for p := range pm.lostPorts {
		ports = append(ports, p)
		delete(pm.lostPorts, p)
	}
	sort.Ints(ports)
	return ports
}

// RefreshEphemeralRange re-reads the ephemeral range from the platform.
func (pm *PortManager) RefreshEphemeralRange() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.ephLo, pm.ephHi, _ = EphemeralRange()
}

// parseAddrPort extracts the port from a local-address string as reported
// by the platform tools. One shared implementation for every OS variant
// (G13 — freebsd and windows each carried a private copy):
// "*:80", "0.0.0.0:80", "[::]:80", "*.80" (sockstat), "127.0.0.1.80".
func parseAddrPort(addr string) int {
	sep := strings.LastIndex(addr, ":")
	if sep < 0 {
		sep = strings.LastIndex(addr, ".")
	}
	if sep < 0 {
		return 0
	}
	p, err := strconv.Atoi(addr[sep+1:])
	if err != nil || p <= 0 {
		return 0
	}
	return p
}
