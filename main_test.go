package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"fuzzpot/config"
	"fuzzpot/logger"
	"fuzzpot/portscan"
)

// timeoutErr is a net.Error stub whose Timeout() reports the configured value.
type timeoutErr struct{ ok bool }

func (e *timeoutErr) Error() string   { return "simulated timeout" }
func (e *timeoutErr) Timeout() bool   { return e.ok }
func (e *timeoutErr) Temporary() bool { return e.ok }

func TestIsTemporaryAcceptError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"net timeout", &timeoutErr{ok: true}, true},
		{"wrapped net timeout", fmt.Errorf("accept: %w", &timeoutErr{ok: true}), true},
		{"conn aborted", syscall.ECONNABORTED, true},
		{"wrapped emfile", fmt.Errorf("accept: %w", syscall.EMFILE), true},
		{"enfile", syscall.ENFILE, true},
		{"eagain", syscall.EAGAIN, true},
		{"eintr", syscall.EINTR, true},
		{"generic error", errors.New("some permanent failure"), false},
		{"net error without timeout", &timeoutErr{ok: false}, false},
	}
	for _, tc := range cases {
		if got := isTemporaryAcceptError(tc.err); got != tc.want {
			t.Errorf("%s: isTemporaryAcceptError() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestAcceptLoop_CtxCancelDuringIdleAccept(t *testing.T) {
	slogLogger = defaultSlogLogger()

	// Guards the new backoff control flow: the loop must still exit
	// promptly on ctx cancel while sitting in Accept/backoff.
	var stats statsCounters
	conns := newConnectionTracker(4)

	cfg := &config.Config{
		Capture: config.CaptureConfig{ReadTimeoutSec: 1, MaxPayloadSize: 1024},
	}
	tmpDir := t.TempDir()
	log, err := logger.New(tmpDir, "backoff.log", 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	secLog, err := logger.NewSecurityLogger(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer secLog.Close()

	pm := portscan.NewPortManager(nil)
	ctx, cancel := context.WithCancel(context.Background())

	port := freeTCPPort(t)
	done := make(chan error, 1)
	go func() {
		done <- listenPort(ctx, port, cfg, pm, log, secLog, &stats, conns, newHitReporter(io.Discard), newFairnessLimiter(0, 0))
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("listenPort returned error on shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listenPort did not return after ctx cancel")
	}
}

// freeTCPPort asks the OS for a currently free TCP port.
// TestMain keeps every test binary off non-loopback interfaces.
//
// `go test` executes the package binary from a new %TEMP%\go-build* directory
// each run, and Windows Firewall prompts once per executable path when it
// listens on a wildcard address. Binding 127.0.0.1 avoids the prompt entirely
// while still exercising the real listen/accept path.
func TestMain(m *testing.M) {
	listenHost = "127.0.0.1"
	os.Exit(m.Run())
}

func TestListenAddress(t *testing.T) {
	prev := listenHost
	t.Cleanup(func() { listenHost = prev })

	listenHost = ""
	if got := listenAddress(8080); got != ":8080" {
		t.Fatalf("production address = %q, want \":8080\"", got)
	}

	listenHost = "127.0.0.1"
	if got := listenAddress(8080); got != "127.0.0.1:8080" {
		t.Fatalf("test address = %q, want \"127.0.0.1:8080\"", got)
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}

func TestTruncate_ShortString(t *testing.T) {
	got := truncate("hello", 10)
	if got != "hello" {
		t.Errorf("truncate(\"hello\", 10) = %q, want \"hello\"", got)
	}
}

func TestTruncate_ExactLength(t *testing.T) {
	got := truncate("hello", 5)
	if got != "hello" {
		t.Errorf("truncate(\"hello\", 5) = %q, want \"hello\"", got)
	}
}

func TestTruncate_JustOverLimit(t *testing.T) {
	got := truncate("hello world", 5)
	want := "hello..."
	if got != want {
		t.Errorf("truncate(\"hello world\", 5) = %q, want %q", got, want)
	}
}

func TestTruncate_EmptyString(t *testing.T) {
	got := truncate("", 10)
	if got != "" {
		t.Errorf("truncate(\"\", 10) = %q, want \"\"", got)
	}
}

func TestTruncate_ZeroMax(t *testing.T) {
	got := truncate("hello", 0)
	if got != "..." {
		t.Errorf("truncate(\"hello\", 0) = %q, want \"...\"", got)
	}
}

func TestTruncate_RuneSafe_Chinese(t *testing.T) {
	// Chinese characters are 3 bytes each in UTF-8
	s := "你好世界"
	got := truncate(s, 2)
	if len(got) == 0 {
		t.Fatal("truncate returned empty string")
	}
	// Should have 2 runes + "..."
	if got != "你好..." {
		t.Errorf("truncate(\"你好世界\", 2) = %q, want \"你好...\"", got)
	}
}

func TestTruncate_RuneSafe_Emoji(t *testing.T) {
	// Emoji can be 4 bytes
	s := "🚀🔥🎉"
	got := truncate(s, 2)
	if got != "🚀🔥..." {
		t.Errorf("truncate(\"🚀🔥🎉\", 2) = %q, want \"🚀🔥...\"", got)
	}
}

func TestTruncate_RuneSafe_MixedASCII(t *testing.T) {
	// Mix of ASCII and multi-byte
	s := "Hello, 世界! 🌍"
	got := truncate(s, 8)
	// Should produce 8 runes + "..."
	// H(1) e(2) l(3) l(4) o(5) ,(6) ' '(7) 世(8) → stop
	expected := "Hello, 世..."
	if got != expected {
		t.Errorf("truncate(%q, 8) = %q, want %q", s, got, expected)
	}
}

func TestTruncate_RuneSafe_ASCIIBoundary(t *testing.T) {
	// Regression test: ASCII-only should behave identically
	s := "abcdefghijklmnop"
	got := truncate(s, 10)
	want := "abcdefghij..."
	if got != want {
		t.Errorf("truncate(%q, 10) = %q, want %q", s, got, want)
	}
}

func TestTruncate_RuneSafe_NoCorruption(t *testing.T) {
	// Verify the result is valid UTF-8 after truncation
	s := "Hello 你好 👋"
	got := truncate(s, 8)
	if len(got) == 0 {
		t.Fatal("truncate returned empty")
	}
	// Should end with "..."
	if got[len(got)-3:] != "..." {
		t.Errorf("truncate result doesn't end with \"...\": %q", got)
	}
}

// TestEndToEnd_FullPipeline starts a real TCP listener, connects with net.Dial,
// sends a payload, and verifies the full chain: listener → capture → log to disk.
func TestEndToEnd_FullPipeline(t *testing.T) {
	tmpDir := t.TempDir()

	// --- Setup ---

	// Initialize the structured logger (normally set in main())
	slogLogger = defaultSlogLogger()

	// Create file logger for payloads
	log, err := logger.New(tmpDir, "payloads.log", 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	// Create security logger
	secLog, err := logger.NewSecurityLogger(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer secLog.Close()

	// Minimal config: capture on one port
	cfg := &config.Config{
		Capture: config.CaptureConfig{
			ReadTimeoutSec: 5,
			MaxPayloadSize: 65536,
			LogHexPayload:  true,
		},
		Logging: config.LoggingConfig{
			Dir:  tmpDir,
			File: "payloads.log",
		},
	}

	// Stats (same counters handleConnection increments)
	var stats statsCounters

	// Connection tracker (generous limit)
	conns := newConnectionTracker(100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- Start listener on random port ---
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	// Accept connections in a goroutine, feeding them to handleConnection
	errCh := make(chan error, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					errCh <- nil
					return
				}
				continue
			}
			stats.connections.Add(1)
			conns.acquire()
			go handleConnection(conn, port, cfg, log, &stats, conns, newHitReporter(io.Discard))
		}
	}()

	// --- Client: connect and send payload ---
	payload := []byte("GET / HTTP/1.1\r\nHost: evil.example.com\r\nUser-Agent: GoTest/1.0\r\n\r\n")

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Write(payload)
	if err != nil {
		t.Fatal(err)
	}
	client.Close()

	// Give the server time to process
	time.Sleep(200 * time.Millisecond)

	// --- Verify ---

	// Stats should show 1 connection, 1 payload
	if got := stats.connections.Load(); got != 1 {
		t.Errorf("connections = %d, want 1", got)
	}
	if got := stats.payloads.Load(); got != 1 {
		t.Errorf("payloads = %d, want 1", got)
	}
	if got := stats.errors.Load(); got != 0 {
		t.Errorf("errors = %d, want 0", got)
	}

	// Log file should exist and contain valid JSON
	logFile := log.Path()
	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("log file is empty — no event was written")
	}

	// Parse JSON line
	var entry LogEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("invalid JSON in log: %v\ncontent: %s", err, string(data))
	}

	// Verify fields
	if entry.SourceIP != "127.0.0.1" {
		t.Errorf("SourceIP = %q, want \"127.0.0.1\"", entry.SourceIP)
	}
	if entry.Size != len(payload) {
		t.Errorf("Size = %d, want %d", entry.Size, len(payload))
	}
	if entry.DestPort != port {
		t.Errorf("DestPort = %d, want %d", entry.DestPort, port)
	}
	if entry.Proto != "tcp" {
		t.Errorf("Proto = %q, want \"tcp\"", entry.Proto)
	}
	if entry.PayloadSHA256 == "" {
		t.Error("PayloadSHA256 should not be empty")
	}
	if len(entry.PayloadSHA256) != 64 {
		t.Errorf("PayloadSHA256 length = %d, want 64", len(entry.PayloadSHA256))
	}
	if entry.Hex == "" {
		t.Error("Hex should not be empty when LogHexPayload=true")
	}
	wantHex := fmt.Sprintf("%x", payload)
	if entry.Hex != wantHex {
		t.Errorf("Hex = %q, want %q", entry.Hex, wantHex)
	}

	// Verify the log file path is correct
	wantPath := filepath.Join(tmpDir, "payloads.log")
	if log.Path() != wantPath {
		t.Errorf("log path = %q, want %q", log.Path(), wantPath)
	}

	cancel()
	ln.Close()
}

func TestEndToEnd_Throttling(t *testing.T) {
	tmpDir := t.TempDir()
	slogLogger = defaultSlogLogger()

	log, err := logger.New(tmpDir, "throttle_test.log", 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	secLog, err := logger.NewSecurityLogger(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer secLog.Close()

	cfg := &config.Config{
		Capture: config.CaptureConfig{
			ReadTimeoutSec: 5,
			MaxPayloadSize: 65536,
		},
	}

	var stats statsCounters

	// Tiny tracker (1 slot) to force throttling
	conns := newConnectionTracker(1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					errCh <- nil
					return
				}
				continue
			}
			stats.connections.Add(1)

			// Try to acquire — full tracker means throttle
			if conns.acquire() {
				go handleConnection(conn, 0, cfg, log, &stats, conns, newHitReporter(io.Discard))
			} else {
				stats.throttled.Add(1)
				conn.Close()
			}
		}
	}()

	// First connection: acquires the semaphore slot
	conn1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()
	time.Sleep(50 * time.Millisecond)

	// Second connection: should be throttled (semaphore full)
	conn2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn2.Close()
	time.Sleep(50 * time.Millisecond)

	if stats.throttled.Load() == 0 {
		t.Error("expected at least 1 throttled connection")
	}
	if stats.connections.Load() < 2 {
		t.Errorf("connections = %d, want >= 2", stats.connections.Load())
	}

	cancel()
}

// defaultSlogLogger returns a silent slog.Logger for testing.
func defaultSlogLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestEndToEnd_LogHexPayloadDisabled(t *testing.T) {
	tmpDir := t.TempDir()
	slogLogger = defaultSlogLogger()

	log, err := logger.New(tmpDir, "nohex.log", 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	// LogHexPayload is false — Hex field should be omitted
	cfg := &config.Config{
		Capture: config.CaptureConfig{
			ReadTimeoutSec: 5,
			MaxPayloadSize: 65536,
			LogHexPayload:  false,
		},
	}

	var stats statsCounters

	conns := newConnectionTracker(100)
	cancel := func() {} // no-op, ln.Close() suffices for cleanup

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			stats.connections.Add(1)
			conns.acquire()
			go handleConnection(conn, port, cfg, log, &stats, conns, newHitReporter(io.Discard))
		}
	}()

	payload := []byte("no-hex-test-payload")
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client.Write(payload)
	client.Close()

	time.Sleep(200 * time.Millisecond)

	data, err := os.ReadFile(log.Path())
	if err != nil {
		t.Fatal(err)
	}

	var entry LogEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("invalid JSON: %v\ncontent: %s", err, string(data))
	}

	// Hex should be empty (omitted from JSON)
	if entry.Hex != "" {
		t.Errorf("Hex should be empty when LogHexPayload=false, got %q", entry.Hex)
	}

	// Other fields should still be present
	if entry.SourceIP != "127.0.0.1" {
		t.Errorf("SourceIP = %q", entry.SourceIP)
	}
	if entry.Size != len(payload) {
		t.Errorf("Size = %d, want %d", entry.Size, len(payload))
	}
	if entry.PayloadSHA256 == "" {
		t.Error("PayloadSHA256 should still be present even without Hex")
	}

	cancel()
	ln.Close()
}

// panicConn wraps a net.Conn and panics on Read to test recovery.
type panicConn struct {
	net.Conn
}

func (p *panicConn) Read([]byte) (int, error) {
	panic("simulated panic in capture")
}

func (p *panicConn) Close() error { return nil }

func TestHandleConnection_PanicRecovery(t *testing.T) {
	slogLogger = defaultSlogLogger()

	var stats statsCounters

	// Create a base connection just for type assertions
	server, _ := net.Pipe()
	defer server.Close()

	conn := &panicConn{Conn: server}
	cfg := &config.Config{
		Capture: config.CaptureConfig{
			ReadTimeoutSec: 1,
			MaxPayloadSize: 1024,
		},
	}

	// Use a buffered channel to detect completion
	done := make(chan struct{}, 1)
	conns := newConnectionTracker(1)
	conns.acquire() // reserve the slot the handler will release

	go func() {
		handleConnection(conn, 9999, cfg, nil, &stats, conns, newHitReporter(io.Discard))
		done <- struct{}{}
	}()

	select {
	case <-done:
		// Good — didn't panic
	case <-time.After(time.Second):
		t.Fatal("handleConnection hung after panic recovery")
	}

	if got := stats.errors.Load(); got != 1 {
		t.Errorf("errors = %d, want 1 (panic should be counted)", got)
	}
}

// ── connectionTracker (DEFECT-03) ─────────────────────────────────────────

func TestConnectionTracker_AcquireRespectsCapacity(t *testing.T) {
	conns := newConnectionTracker(2)
	if !conns.acquire() {
		t.Fatal("first acquire failed")
	}
	if !conns.acquire() {
		t.Fatal("second acquire failed")
	}
	if conns.acquire() {
		t.Fatal("acquire succeeded past capacity; throttling would break")
	}
	conns.release()
	if !conns.acquire() {
		t.Fatal("acquire failed after a slot was released")
	}
	conns.release()
	conns.release()
}

// wait() must block while a handler is still running. Without this, shutdown
// closes the log file underneath an in-flight WriteEventTyped call.
func TestConnectionTracker_WaitBlocksUntilRelease(t *testing.T) {
	conns := newConnectionTracker(2)
	conns.acquire()

	waited := make(chan int, 1)
	go func() { waited <- conns.wait(5 * time.Second) }()

	select {
	case n := <-waited:
		t.Fatalf("wait() returned %d while a handler was still in flight", n)
	case <-time.After(80 * time.Millisecond):
		// Expected: still blocked.
	}

	conns.release()

	select {
	case n := <-waited:
		if n != 0 {
			t.Fatalf("wait() = %d outstanding handlers, want 0", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wait() did not return after the last handler released")
	}
}

// A hung handler must not block shutdown forever; wait() reports the remainder.
func TestConnectionTracker_WaitTimesOut(t *testing.T) {
	conns := newConnectionTracker(1)
	conns.acquire()

	if n := conns.wait(20 * time.Millisecond); n != 1 {
		t.Fatalf("wait() = %d outstanding handlers, want 1", n)
	}
	conns.release()
}

// ── app wiring and supervision loop (D-08) ────────────────────────────────

func newTestApp(t *testing.T, cfg *config.Config, targets []int) *app {
	t.Helper()
	tmpDir := t.TempDir()

	log, err := logger.New(tmpDir, "app.log", 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })

	secLog, err := logger.NewSecurityLogger(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { secLog.Close() })

	return &app{
		cfg:     cfg,
		log:     log,
		secLog:  secLog,
		pm:      portscan.NewPortManager(cfg.Ports.Exclude),
		targets: targets,
		conns:   newConnectionTracker(4),
	}
}

func TestPortRanges_FlattensConfig(t *testing.T) {
	cfg := &config.Config{Ports: config.PortsConfig{
		Ranges: []config.PortRange{{From: 20, To: 22}, {From: 80, To: 80}},
	}}

	got := portRanges(cfg)
	want := [][2]int{{20, 22}, {80, 80}}
	if len(got) != len(want) {
		t.Fatalf("portRanges() returned %d ranges, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("range %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestNewApp_ResolvesSortedTargetsAndExcludes(t *testing.T) {
	cfg := &config.Config{Ports: config.PortsConfig{
		Ranges:  []config.PortRange{{From: 2000, To: 2004}},
		Exclude: []int{2002},
	}}

	a, targets := newApp(cfg, portRanges(cfg))

	if a.conns == nil {
		t.Fatal("newApp did not build a connection tracker")
	}
	if len(targets) == 0 {
		t.Fatal("newApp resolved zero targets")
	}
	for i := 1; i < len(targets); i++ {
		if targets[i-1] >= targets[i] {
			t.Fatalf("targets not sorted: %v", targets)
		}
	}
	for _, p := range targets {
		if p == 2002 {
			t.Fatal("excluded port 2002 appears in targets")
		}
	}
	if len(a.targets) != len(targets) {
		t.Fatalf("app.targets has %d entries, returned %d", len(a.targets), len(targets))
	}
}

// run() must return promptly on ctx cancel and drain before returning. With no
// targets there are no listeners to bind, which keeps the test fast and
// port-free while still exercising the supervision loop and shutdown path.
func TestAppRun_ReturnsAfterCancel(t *testing.T) {
	slogLogger = defaultSlogLogger()
	cfg := &config.Config{Refresh: config.RefreshConfig{IntervalSec: 5}}
	a := newTestApp(t, cfg, nil)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- a.run(ctx)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("run() returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not return after ctx cancel")
	}
}

// newApp leaves the loggers unattached so --dry-run can exit before opening
// any file. run() must reject that state instead of panicking inside a handler.
func TestAppRun_RejectsMissingLoggers(t *testing.T) {
	cfg := &config.Config{Refresh: config.RefreshConfig{IntervalSec: 5}}
	a, _ := newApp(cfg, nil)

	err := a.run(context.Background())
	if err == nil {
		t.Fatal("run() accepted an app with no loggers")
	}
	if !strings.Contains(err.Error(), "loggers must be attached") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// drain() must wait for a handler that is still writing, then report zero.
func TestAppDrain_WaitsForInFlightHandler(t *testing.T) {
	slogLogger = defaultSlogLogger()
	a := newTestApp(t, &config.Config{}, nil)

	// Simulate one handler holding a slot.
	a.conns.acquire()
	go func() {
		time.Sleep(60 * time.Millisecond)
		a.conns.release()
	}()

	var listeners sync.WaitGroup
	start := time.Now()
	a.drain(&listeners)
	elapsed := time.Since(start)

	if elapsed < 40*time.Millisecond {
		t.Fatalf("drain() returned in %v; it did not wait for the in-flight handler", elapsed)
	}
	if n := a.conns.wait(time.Second); n != 0 {
		t.Fatalf("%d handler(s) still outstanding after drain", n)
	}
}

func TestAppReportStats_ExitsOnCancel(t *testing.T) {
	slogLogger = defaultSlogLogger()
	a := newTestApp(t, &config.Config{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	done := make(chan struct{})
	go func() {
		a.reportStats(ctx, ticker)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reportStats did not exit after ctx cancel")
	}
}

func TestAppCheckConflicts_NoConflictsIsQuiet(t *testing.T) {
	slogLogger = defaultSlogLogger()
	a := newTestApp(t, &config.Config{}, nil)
	// Nothing is listening, so this must be a no-op rather than a panic.
	a.checkConflicts()
}

func TestWatchSignals_ShutdownSignalCancels(t *testing.T) {
	slogLogger = defaultSlogLogger()
	a := newTestApp(t, &config.Config{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	a.watchSignals(sigCh, cancel)

	sigCh <- syscall.SIGTERM

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown signal did not cancel the context")
	}
}

func TestWatchSignals_HealthSignalDoesNotCancel(t *testing.T) {
	slogLogger = defaultSlogLogger()
	a := newTestApp(t, &config.Config{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	a.watchSignals(sigCh, cancel)

	// Anything other than INT/TERM is treated as the health-check signal.
	sigCh <- syscall.Signal(99)

	select {
	case <-ctx.Done():
		t.Fatal("health signal must not cancel the context")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 3, "hel..."},
		{"héllo", 5, "héllo"},  // rune-aware: 5 runes, not 6 bytes
		{"héllo", 3, "hél..."}, // must not split a multi-byte rune
		{"", 0, ""},
	}
	for _, tc := range cases {
		if got := truncate(tc.in, tc.max); got != tc.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}
}

func TestFormatPortList(t *testing.T) {
	if got := formatPortList(nil); got != "" {
		t.Errorf("formatPortList(nil) = %q, want empty", got)
	}
	if got := formatPortList([]int{1, 22, 80}); got != "1, 22, 80" {
		t.Errorf("formatPortList = %q, want %q", got, "1, 22, 80")
	}
}

func TestTruncatePortList(t *testing.T) {
	if got := truncatePortList(nil, 8); got != "(none)" {
		t.Errorf("empty list = %q, want (none)", got)
	}
	if got := truncatePortList([]int{1, 2}, 8); got != "(1, 2)" {
		t.Errorf("short list = %q, want (1, 2)", got)
	}
	if got := truncatePortList([]int{1, 2, 3, 4, 5}, 3); got != "(1, 2, 3, +2 more)" {
		t.Errorf("truncated list = %q, want (1, 2, 3, +2 more)", got)
	}
}

func TestShowPortSummary_EmptyAndLong(t *testing.T) {
	// Writes to stderr; the contract under test is "does not panic and does not
	// index out of range" for both the empty and the >20 port shapes.
	showPortSummary(nil)
	showPortSummary([]int{1})
	many := make([]int, 25)
	for i := range many {
		many[i] = 1000 + i
	}
	showPortSummary(many)
}

func TestShowConflictAnalysis_EmptyRanges(t *testing.T) {
	cfg := &config.Config{}
	pm := portscan.NewPortManager(nil)
	showConflictAnalysis(pm, nil, cfg)
}

func TestPrintBanner_DoesNotPanic(t *testing.T) {
	printBanner()
}

// ── hitReporter (D-10) ────────────────────────────────────────────────────

func TestHitReporter_LimitsBurstPerWindow(t *testing.T) {
	var buf bytes.Buffer
	r := newHitReporter(&buf)
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return fixed }

	for i := 0; i < hitConsoleBurst+5; i++ {
		r.report("10.0.0.1", 40000+i, 22, 10, "x")
	}

	if got := strings.Count(buf.String(), "[hit] 10.0.0.1"); got != hitConsoleBurst {
		t.Fatalf("emitted %d hit lines, want %d (burst cap)", got, hitConsoleBurst)
	}
}

func TestHitReporter_ReportsSuppressedOnNextWindow(t *testing.T) {
	var buf bytes.Buffer
	r := newHitReporter(&buf)
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return fixed }

	const extra = 3
	for i := 0; i < hitConsoleBurst+extra; i++ {
		r.report("10.0.0.1", 40000+i, 22, 10, "x")
	}

	buf.Reset()
	r.now = func() time.Time { return fixed.Add(2 * time.Second) }
	r.report("10.0.0.2", 50000, 22, 10, "y")

	out := buf.String()
	if !strings.Contains(out, "3 more hit(s) suppressed") {
		t.Fatalf("suppression summary missing from output: %q", out)
	}
	if !strings.Contains(out, "10.0.0.2") {
		t.Fatalf("first hit of the new window was not printed: %q", out)
	}
}

// drain() must also wait for listeners to stop accepting before it returns.
func TestAppDrain_WaitsForListeners(t *testing.T) {
	slogLogger = defaultSlogLogger()
	a := newTestApp(t, &config.Config{}, nil)

	var listeners sync.WaitGroup
	listeners.Add(1)
	go func() {
		time.Sleep(60 * time.Millisecond)
		listeners.Done()
	}()

	start := time.Now()
	a.drain(&listeners)
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("drain() returned in %v; it did not wait for listeners", elapsed)
	}
}

// ── Resource limits (G3/G4) ───────────────────────────────────────────────

func TestConnectionTracker_ByteBudget(t *testing.T) {
	// Three reservations fit; the fourth is refused even though the
	// semaphore has room for ten.
	tr := newConnectionTracker(10, withByteBudget(300, 100))

	for i := 0; i < 3; i++ {
		if !tr.acquire() {
			t.Fatalf("acquire %d rejected inside the byte budget", i)
		}
	}
	if tr.acquire() {
		t.Fatal("acquire succeeded past the byte budget")
	}

	tr.release()
	if !tr.acquire() {
		t.Fatal("release did not return the reservation")
	}
	tr.release()
	tr.release()
	tr.release()

	if got := tr.bytesInUse.Load(); got != 0 {
		t.Fatalf("bytesInUse = %d after releasing everything, want 0", got)
	}
}

func TestConnectionTracker_ByteBudgetDoesNotLeakOnSemaphoreFull(t *testing.T) {
	tr := newConnectionTracker(1, withByteBudget(1<<20, 100))
	if !tr.acquire() {
		t.Fatal("first acquire failed")
	}
	if tr.acquire() {
		t.Fatal("second acquire should fail on the semaphore")
	}
	tr.release()
	if got := tr.bytesInUse.Load(); got != 0 {
		t.Fatalf("bytesInUse = %d, want 0 (failed acquire leaked a reservation)", got)
	}
}

func TestFairnessLimiter_PerPortCap(t *testing.T) {
	f := newFairnessLimiter(2, 0)

	if !f.tryAcquire(8080, "203.0.113.1") || !f.tryAcquire(8080, "203.0.113.2") {
		t.Fatal("first two connections to the port must be admitted")
	}
	if f.tryAcquire(8080, "203.0.113.3") {
		t.Fatal("third connection to the same port must be rejected")
	}
	// Another port is unaffected.
	if !f.tryAcquire(8081, "203.0.113.3") {
		t.Fatal("a different port must still be admitted")
	}

	f.release(8080, "203.0.113.1")
	if !f.tryAcquire(8080, "203.0.113.3") {
		t.Fatal("release did not free a per-port slot")
	}
}

func TestFairnessLimiter_PerIPCap(t *testing.T) {
	f := newFairnessLimiter(0, 1)

	if !f.tryAcquire(8080, "203.0.113.9") {
		t.Fatal("first connection from the IP must be admitted")
	}
	if f.tryAcquire(8081, "203.0.113.9") {
		t.Fatal("second connection from the same IP must be rejected")
	}
	if !f.tryAcquire(8080, "203.0.113.10") {
		t.Fatal("a different IP must still be admitted")
	}

	f.release(8080, "203.0.113.9")
	if !f.tryAcquire(8081, "203.0.113.9") {
		t.Fatal("release did not free a per-IP slot")
	}
}

func TestFairnessLimiter_ZeroCapsAreUnlimited(t *testing.T) {
	f := newFairnessLimiter(0, 0)
	for i := 0; i < 100; i++ {
		if !f.tryAcquire(8080, "203.0.113.9") {
			t.Fatal("zero caps must not limit")
		}
	}
}

func TestHandlerReservationScalesWithPayload(t *testing.T) {
	small := handlerReservation(&config.Config{Capture: config.CaptureConfig{MaxPayloadSize: 1024}})
	if small != 64<<10 {
		t.Fatalf("small payload reservation = %d, want the 64 KiB floor", small)
	}
	large := handlerReservation(&config.Config{Capture: config.CaptureConfig{MaxPayloadSize: 65536}})
	if large != 65536*8 {
		t.Fatalf("64 KiB payload reservation = %d, want %d", large, 65536*8)
	}
}
