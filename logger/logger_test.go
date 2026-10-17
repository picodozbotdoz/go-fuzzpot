package logger

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteEventTyped_JSONEscaping(t *testing.T) {
	tmpDir := t.TempDir()
	log, err := New(tmpDir, "test.log", 1, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	// Test event with characters that require JSON escaping
	type TestEvent struct {
		Msg string `json:"msg"`
	}

	testCases := []struct {
		name         string
		input        string
		wantContains string
	}{
		{"quote", `hello"world`, `\"`},
		{"backslash", `path\to\file`, `\\`},
		{"newline", "line1\nline2", `\n`},
		{"tab", "col1\tcol2", `\t`},
		{"unicode", "café", "café"}, // UTF-8 should pass through
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			event := TestEvent{Msg: tc.input}
			if err := log.WriteEventTyped(event); err != nil {
				t.Errorf("WriteEventTyped() error = %v", err)
			}

			// Read back and verify JSON is valid
			content, err := os.ReadFile(log.Path())
			if err != nil {
				t.Fatal(err)
			}

			// Should be valid JSON line
			if !contains(string(content), tc.wantContains) {
				t.Errorf("expected %q in output, got: %s", tc.wantContains, string(content))
			}
		})
	}
}

func TestWriteEventTyped_ValidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	log, err := New(tmpDir, "test.log", 1, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	type TestEvent struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	event := TestEvent{Name: "test", Value: 42}
	if err := log.WriteEventTyped(event); err != nil {
		t.Fatalf("WriteEventTyped() error = %v", err)
	}

	content, err := os.ReadFile(log.Path())
	if err != nil {
		t.Fatal(err)
	}

	// Verify the output is valid JSON
	var result TestEvent
	if err := json.Unmarshal(content, &result); err != nil {
		t.Errorf("output is not valid JSON: %v, got: %s", err, string(content))
	}

	if result.Name != "test" || result.Value != 42 {
		t.Errorf("unmarshal mismatch: got %+v", result)
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return len(substr) == 0
}

func TestRotate_TriggersAfterSizeLimit(t *testing.T) {
	tmpDir := t.TempDir()
	log, err := New(tmpDir, "rotate_test.log", 1, 5) // 1MB rotation, keep 5
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	// Rotation is checked before writing. First write fills up the file,
	// second write triggers the rotation check.
	data := make([]byte, 1024*1024) // 1MB
	for i := range data {
		data[i] = 'A'
	}
	// First write: fills to 1MB
	if err := log.WriteRaw(string(data)); err != nil {
		t.Fatal(err)
	}
	// Second write: triggers rotation check (written >= rotSize)
	if err := log.WriteRaw("trigger rotation"); err != nil {
		t.Fatal(err)
	}

	// Check that a rotated file exists
	pattern := log.Path() + ".*"
	matches, _ := filepath.Glob(pattern)
	if len(matches) == 0 {
		t.Fatal("expected at least one rotated file after exceeding size limit")
	}

	// Verify the main log file was recreated
	info, err := os.Stat(log.Path())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("main log file size = %d bytes", info.Size())
}

func TestRotate_CreatesTimestampedBackup(t *testing.T) {
	tmpDir := t.TempDir()
	log, err := New(tmpDir, "rotate_ts.log", 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	// Force rotation by writing enough data across two writes
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = 'B'
	}
	// First write: fills to ~1MB
	if err := log.WriteRaw(string(data)); err != nil {
		t.Fatal(err)
	}
	// Second write: triggers rotation
	if err := log.WriteRaw("trigger"); err != nil {
		t.Fatal(err)
	}

	// Check rotated file matches timestamp pattern
	matches, _ := filepath.Glob(log.Path() + ".*")
	if len(matches) == 0 {
		t.Fatal("expected rotated file")
	}
	// Pattern should be YYYYMMDD-HHMMSS
	match := matches[0]
	if len(match) < 16 {
		t.Fatalf("rotated filename %q doesn't have timestamp suffix", match)
	}
	ts := match[len(match)-15:]
	t.Logf("found rotated file: %s (timestamp suffix: %s)", match, ts)
	// Just verify the suffix looks like a timestamp pattern
	if len(ts) != 15 || ts[8] != '-' {
		t.Errorf("timestamp suffix %q doesn't match YYYYMMDD-HHMMSS pattern", ts)
	}
}

func TestPruneOldLogs_RemovesOldest(t *testing.T) {
	tmpDir := t.TempDir()
	log, err := New(tmpDir, "prune_test.log", 100, 3) // keep 3 files max
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	// Create several rotated log files manually with different timestamps
	// The prune function matches files like "prune_test.log.YYYYMMDD-HHMMSS"
	basePath := log.Path()
	// Create 5 rotated files with different ages
	rotatedFiles := []string{
		basePath + ".20250101-000000",
		basePath + ".20250201-000000",
		basePath + ".20250301-000000",
		basePath + ".20250401-000000",
		basePath + ".20250501-000000",
	}
	for _, f := range rotatedFiles {
		if err := os.WriteFile(f, []byte("old log data"), 0644); err != nil {
			t.Fatal(err)
		}
		// Set modtime to match the filename date
		tm, _ := time.Parse("20060102-150405", f[len(f)-15:])
		os.Chtimes(f, tm, tm)
	}

	// Trigger pruning
	log.mu.Lock()
	log.pruneOldLogs()
	log.mu.Unlock()

	// Should keep only 2 oldest removed, 3 newest remain
	matches, _ := filepath.Glob(basePath + ".*")
	if len(matches) > 3 {
		t.Errorf("expected at most 3 rotated files, got %d: %v", len(matches), matches)
	}
}

func TestPruneOldLogs_NoopWhenUnderLimit(t *testing.T) {
	tmpDir := t.TempDir()
	log, err := New(tmpDir, "prune_noop.log", 100, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	// Create only 2 rotated files (under limit of 10)
	basePath := log.Path()
	files := []string{
		basePath + ".20250101-000000",
		basePath + ".20250201-000000",
	}
	for _, f := range files {
		if err := os.WriteFile(f, []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	log.mu.Lock()
	log.pruneOldLogs()
	log.mu.Unlock()

	matches, _ := filepath.Glob(basePath + ".*")
	if len(matches) != 2 {
		t.Errorf("expected 2 rotated files (under limit), got %d", len(matches))
	}
}

func TestKeepFilesZeroMeansUnlimited(t *testing.T) {
	tmpDir := t.TempDir()
	log, err := New(tmpDir, "unlimited.log", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	if log.maxFiles != 0 {
		t.Errorf("maxFiles = %d, want 0 (unlimited), explicit 0 must not be coerced to the default", log.maxFiles)
	}

	// With unlimited retention, pruning must never remove rotated files.
	basePath := log.Path()
	for i := 0; i < 15; i++ {
		rotated := fmt.Sprintf("%s.20250101-%06d", basePath, i)
		if err := os.WriteFile(rotated, []byte("old log data"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	log.mu.Lock()
	log.pruneOldLogs()
	log.mu.Unlock()

	matches, _ := filepath.Glob(basePath + ".*")
	if len(matches) != 15 {
		t.Errorf("expected all 15 rotated files kept (unlimited), got %d", len(matches))
	}
}

func TestKeepFilesDefaultWhenUnspecified(t *testing.T) {
	tmpDir := t.TempDir()
	log, err := New(tmpDir, "default.log", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	if log.maxFiles != 10 {
		t.Errorf("maxFiles = %d, want default 10 when unspecified", log.maxFiles)
	}
}

func TestNewSecurityLogger(t *testing.T) {
	tmpDir := t.TempDir()
	secLog, err := NewSecurityLogger(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer secLog.Close()

	wantPath := filepath.Join(tmpDir, "security.log")
	if secLog.Path() != wantPath {
		t.Errorf("security log path = %q, want %q", secLog.Path(), wantPath)
	}
}

func TestSecurityLogger_LogThrottled(t *testing.T) {
	tmpDir := t.TempDir()
	secLog, err := NewSecurityLogger(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer secLog.Close()

	secLog.LogThrottled("192.168.1.1:54321", 8080)

	content, err := os.ReadFile(secLog.Path())
	if err != nil {
		t.Fatal(err)
	}

	var event SecurityEvent
	if err := json.Unmarshal(content, &event); err != nil {
		t.Fatalf("invalid JSON: %v, content: %s", err, string(content))
	}

	if event.EventType != EventThrottled {
		t.Errorf("EventType = %q, want %q", event.EventType, EventThrottled)
	}
	if event.RemoteAddr != "192.168.1.1:54321" {
		t.Errorf("RemoteAddr = %q, want %q", event.RemoteAddr, "192.168.1.1:54321")
	}
	if event.Port != 8080 {
		t.Errorf("Port = %d, want %d", event.Port, 8080)
	}
	if event.Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}
}

func TestSecurityLogger_LogConflict(t *testing.T) {
	tmpDir := t.TempDir()
	secLog, err := NewSecurityLogger(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer secLog.Close()

	conflicts := []int{80, 443, 8080}
	secLog.LogConflict(conflicts)

	content, err := os.ReadFile(secLog.Path())
	if err != nil {
		t.Fatal(err)
	}

	var event SecurityEvent
	if err := json.Unmarshal(content, &event); err != nil {
		t.Fatalf("invalid JSON: %v, content: %s", err, string(content))
	}

	if event.EventType != EventConflictDetect {
		t.Errorf("EventType = %q, want %q", event.EventType, EventConflictDetect)
	}
	if len(event.Ports) != 3 || event.Ports[0] != 80 {
		t.Errorf("Ports = %v, want [80 443 8080]", event.Ports)
	}
}

// ── A1-7: rotation overhaul ───────────────────────────────────────────

// rotateNow forces a rotation cycle regardless of size (test helper).
func rotateNow(t *testing.T, log *Logger) {
	t.Helper()
	log.mu.Lock()
	defer log.mu.Unlock()
	if err := log.rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
}

// Contract test (pairs with fuzz-sec-intel TestRotationSafety): rotation
// is rename-based — the rotated file survives under a
// <file>.YYYYMMDD-HHMMSS sibling name with its content intact, and the
// live log file is recreated empty, so a tailer can drain the sibling.
func TestRotationIsRenameBased_AnalyzerCanDrain(t *testing.T) {
	tmpDir := t.TempDir()
	log, err := New(tmpDir, "contract.log", 10, 5)
	if err != nil {
		t.Fatal(err)
	}

	if err := log.WriteRaw("event-one"); err != nil {
		t.Fatal(err)
	}
	rotateNow(t, log)

	matches, _ := filepath.Glob(filepath.Join(tmpDir, "contract.log.2*"))
	if len(matches) != 1 {
		t.Fatalf("expected exactly one rotated sibling, got %v", matches)
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "event-one\n" {
		t.Errorf("rotated sibling content = %q, want %q", string(data), "event-one\n")
	}

	// New events go to a fresh live file, not the rotated sibling
	if err := log.WriteRaw("event-two"); err != nil {
		t.Fatal(err)
	}
	live, _ := os.ReadFile(log.Path())
	if string(live) != "event-two\n" {
		t.Errorf("live file after rotation = %q, want %q", string(live), "event-two\n")
	}
	log.Close()
}

// Same-second rotations must not overwrite each other's backups.
func TestRotationSameSecondNoCollision(t *testing.T) {
	tmpDir := t.TempDir()
	log, err := New(tmpDir, "collide.log", 10, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	rotateNow(t, log)
	rotateNow(t, log) // same wall-clock second most of the time

	matches, _ := filepath.Glob(filepath.Join(tmpDir, "collide.log.*"))
	if len(matches) < 2 {
		t.Fatalf("same-second rotations collided: %v", matches)
	}
}

func TestRotationCompressesAfterDelay(t *testing.T) {
	tmpDir := t.TempDir()
	log, err := NewWithOptions(tmpDir, "gz.log", 10, 5, Options{
		Compress:         true,
		CompressDelaySec: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	if err := log.WriteRaw("compress-me"); err != nil {
		t.Fatal(err)
	}
	rotateNow(t, log)

	deadline := time.Now().Add(5 * time.Second)
	var gzPath string
	for time.Now().Before(deadline) {
		gz, _ := filepath.Glob(filepath.Join(tmpDir, "gz.log.*.gz"))
		plain, _ := filepath.Glob(filepath.Join(tmpDir, "gz.log.2???????-??????"))
		if len(gz) == 1 && len(plain) == 0 {
			gzPath = gz[0]
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if gzPath == "" {
		t.Fatal("rotated file was not compressed to .gz (with plain file removed)")
	}

	f, err := os.Open(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "compress-me\n" {
		t.Errorf("gz content = %q, want %q", string(data), "compress-me\n")
	}
}

func TestPruneCountsCompressedFiles(t *testing.T) {
	tmpDir := t.TempDir()
	log, err := New(tmpDir, "prune_gz.log", 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	base := filepath.Join(tmpDir, "prune_gz.log")
	for _, name := range []string{
		base + ".20250101-000000",
		base + ".20250102-000000.gz",
		base + ".20250103-000000",
	} {
		if err := os.WriteFile(name, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	log.mu.Lock()
	log.pruneOldLogs()
	log.mu.Unlock()

	matches, _ := filepath.Glob(base + ".*")
	if len(matches) != 2 {
		t.Errorf("expected 2 files kept (cap 2, .gz counted), got %d: %v", len(matches), matches)
	}
}

func TestFsyncWritesOption(t *testing.T) {
	tmpDir := t.TempDir()
	log, err := NewWithOptions(tmpDir, "fsync.log", 10, 5, Options{FsyncWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	if err := log.WriteRaw("durability"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(log.Path())
	if string(data) != "durability\n" {
		t.Errorf("content = %q", string(data))
	}
}
