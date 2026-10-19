package portscan

import (
	"testing"
)

func TestPortManager_TargetPorts_ExcludesCorrectly(t *testing.T) {
	// Setup: exclude ports 80, 443; ephemeral 32768-60999
	pm := NewPortManager([]int{80, 443})
	pm.ephLo, pm.ephHi = 32768, 60999

	// Mock used ports: 22, 8080
	// We'll override GetUsedPorts via test helper
	original := GetUsedPorts
	GetUsedPorts = func() map[int]bool {
		return map[int]bool{22: true, 8080: true}
	}
	t.Cleanup(func() { GetUsedPorts = original })

	ranges := [][2]int{{1, 100}, {8000, 8100}, {32768, 32770}}
	targets := pm.TargetPorts(ranges)

	// Should exclude: 22 (used), 80/443 (config), 32768-32770 (ephemeral)
	wantExcluded := map[int]bool{22: true, 80: true, 443: true, 8080: true}
	for _, p := range []int{32768, 32769, 32770} {
		wantExcluded[p] = true
	}

	for _, port := range targets {
		if wantExcluded[port] {
			t.Errorf("TargetPorts() included excluded port %d", port)
		}
		if port < 1 || port > 65535 {
			t.Errorf("TargetPorts() returned invalid port %d", port)
		}
	}

	// Should include: 1-79 (except 22), 81-100, 8000-8079, 8081-8100
	if len(targets) == 0 {
		t.Error("TargetPorts() returned empty list")
	}
}

func TestPortManager_DetectConflicts(t *testing.T) {
	pm := NewPortManager(nil)
	pm.SetListening(8080)
	pm.SetListening(9090)

	// Healthy listeners are never conflicts. The system socket table lists
	// our own sockets, so the old comparison reported every bound port on
	// every tick.
	original := GetUsedPorts
	GetUsedPorts = func() map[int]bool {
		return map[int]bool{8080: true, 9090: true}
	}
	t.Cleanup(func() { GetUsedPorts = original })

	if got := pm.DetectConflicts(); len(got) != 0 {
		t.Fatalf("healthy listeners reported as conflicts: %v", got)
	}

	// A listener that died and could not be rebound is the real signal.
	pm.MarkLost(9090)
	if got := pm.DetectConflicts(); len(got) != 1 || got[0] != 9090 {
		t.Fatalf("DetectConflicts() = %v, want [9090]", got)
	}

	// Reported once, then cleared.
	if got := pm.DetectConflicts(); len(got) != 0 {
		t.Fatalf("conflicts not cleared after reporting: %v", got)
	}

	// A lost port no longer counts as listening.
	if n := pm.ListeningCount(); n != 1 {
		t.Fatalf("ListeningCount() = %d, want 1", n)
	}

	// A successful rebind restores it.
	pm.SetListening(9090)
	if n := pm.ListeningCount(); n != 2 {
		t.Fatalf("ListeningCount() after rebind = %d, want 2", n)
	}
}

func TestIsEphemeral_Boundaries(t *testing.T) {
	tests := []struct {
		port, lo, hi int
		want         bool
	}{
		{32768, 32768, 60999, true},  // low boundary
		{60999, 32768, 60999, true},  // high boundary
		{32767, 32768, 60999, false}, // just below
		{61000, 32768, 60999, false}, // just above
		{1000, 32768, 60999, false},  // well below
		{0, 0, 0, true},              // edge: zero range
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			if got := IsEphemeral(tt.port, tt.lo, tt.hi); got != tt.want {
				t.Errorf("IsEphemeral(%d, %d, %d) = %v, want %v",
					tt.port, tt.lo, tt.hi, got, tt.want)
			}
		})
	}
}
