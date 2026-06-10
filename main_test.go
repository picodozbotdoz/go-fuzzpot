package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fuzzpot/config"
	"fuzzpot/logger"
)

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

	// Stats struct (same shape as in main())
	var stats struct {
		mu          sync.Mutex
		connections int64
		payloads    int64
		errors      int64
		throttled   int64
	}

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
			atomic.AddInt64(&stats.connections, 1)
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
	stats.mu.Lock()
	if stats.connections != 1 {
		t.Errorf("connections = %d, want 1", stats.connections)
	}
	if stats.payloads != 1 {
		t.Errorf("payloads = %d, want 1", stats.payloads)
	}
	if stats.errors != 0 {
		t.Errorf("errors = %d, want 0", stats.errors)
	}
	stats.mu.Unlock()

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

	var stats struct {
		mu          sync.Mutex
		connections int64
		payloads    int64
		errors      int64
		throttled   int64
	}

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
			atomic.AddInt64(&stats.connections, 1)

			// Try to acquire — full semaphore means throttle
			select {
			case connSem <- struct{}{}:
				go handleConnection(conn, 0, cfg, log, &stats, connSem)
			default:
				stats.mu.Lock()
				stats.throttled++
				stats.mu.Unlock()
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

	stats.mu.Lock()
	if stats.throttled == 0 {
		t.Error("expected at least 1 throttled connection")
	}
	if stats.connections < 2 {
		t.Errorf("connections = %d, want >= 2", stats.connections)
	}
	stats.mu.Unlock()

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

	var stats struct {
		mu          sync.Mutex
		connections int64
		payloads    int64
		errors      int64
		throttled   int64
	}

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
			atomic.AddInt64(&stats.connections, 1)
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

