package main

import "sync"

// fairnessLimiter caps how many handlers may run concurrently for one
// destination port and one source IP.
//
// Without it, a single flooded port or a single sender can occupy every slot
// in the global semaphore for the full read timeout, and the other 3999
// ports silently stop capturing. A zero cap means "unlimited", but the
// counters are still maintained so acquire and release stay symmetric.
type fairnessLimiter struct {
	perPortMax int
	perIPMax   int

	mu      sync.Mutex
	perPort map[int]int
	perIP   map[string]int
}

func newFairnessLimiter(perPortMax, perIPMax int) *fairnessLimiter {
	return &fairnessLimiter{
		perPortMax: perPortMax,
		perIPMax:   perIPMax,
		perPort:    make(map[int]int),
		perIP:      make(map[string]int),
	}
}

// tryAcquire reserves a fairness slot for (port, ip). It must be paired with
// release on every path, including when the caller then fails to get a
// global connection slot.
func (f *fairnessLimiter) tryAcquire(port int, ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.perPortMax > 0 && f.perPort[port] >= f.perPortMax {
		return false
	}
	if f.perIPMax > 0 && ip != "" && f.perIP[ip] >= f.perIPMax {
		return false
	}

	f.perPort[port]++
	if ip != "" {
		f.perIP[ip]++
	}
	return true
}

func (f *fairnessLimiter) release(port int, ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if n := f.perPort[port] - 1; n > 0 {
		f.perPort[port] = n
	} else {
		delete(f.perPort, port)
	}
	if ip != "" {
		if n := f.perIP[ip] - 1; n > 0 {
			f.perIP[ip] = n
		} else {
			delete(f.perIP, ip)
		}
	}
}

// inFlight reports the current counters (tests and health output).
func (f *fairnessLimiter) inFlight(port int, ip string) (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.perPort[port], f.perIP[ip]
}
