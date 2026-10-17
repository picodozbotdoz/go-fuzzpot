package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
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
	connSem := make(chan struct{}, 4)

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
		done <- listenPort(ctx, port, cfg, pm, log, secLog, &stats, connSem)
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

	// Connection semaphore (generous limit)
	connSem := make(chan struct{}, 100)
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
			connSem <- struct{}{}
			go handleConnection(conn, port, cfg, log, &stats, connSem)
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

	// Tiny semaphore (1 slot) to force throttling
	connSem := make(chan struct{}, 1)
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

			// Try to acquire — full semaphore means throttle
			select {
			case connSem <- struct{}{}:
				go handleConnection(conn, 0, cfg, log, &stats, connSem)
			default:
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

	connSem := make(chan struct{}, 100)
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
			connSem <- struct{}{}
			go handleConnection(conn, port, cfg, log, &stats, connSem)
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
	connSem := make(chan struct{}, 1)
	connSem <- struct{}{} // pre-fill so the defer release works

	go func() {
		handleConnection(conn, 9999, cfg, nil, &stats, connSem)
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
