//go:build race

package portscan

import (
	"sync"
	"testing"
)

// TestTargetPorts_RaceCondition verifies no data races when calling
// TargetPorts concurrently with SetListening/ClearListening
func TestTargetPorts_RaceCondition(t *testing.T) {
	pm := NewPortManager([]int{80})
	pm.ephLo, pm.ephHi = 32768, 60999

	// Mock GetUsedPorts to avoid platform dependency
	original := GetUsedPorts
	GetUsedPorts = func() map[int]bool {
		return map[int]bool{}
	}
	t.Cleanup(func() { GetUsedPorts = original })

	var wg sync.WaitGroup
	ranges := [][2]int{{1000, 1100}}

	// Goroutine 1: repeatedly call TargetPorts
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = pm.TargetPorts(ranges)
		}
	}()

	// Goroutine 2: modify listening state
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1000; i < 1100; i++ {
			pm.SetListening(i)
			pm.ClearListening(i)
		}
	}()

	wg.Wait()
	// If race detector is enabled, this test will fail if races exist
}
