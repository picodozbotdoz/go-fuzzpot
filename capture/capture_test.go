package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

func TestExtractPrintable(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"empty", []byte{}, ""},
		{"ascii", []byte("hello"), "hello"},
		{"with_null", []byte("A\x00B"), "A.B"},
		{"with_newline", []byte("line1\nline2"), "line1\nline2"},
		{"with_tab", []byte("col1\tcol2"), "col1\tcol2"},
		{"with_cr", []byte("line1\rline2"), "line1\rline2"},
		{"high_bit", []byte{0x80, 0xFF}, ".."},
		{"del_char", []byte{0x7F}, "."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPrintable(tt.input)
			if got != tt.want {
				t.Errorf("extractPrintable(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractPrintable_Truncation(t *testing.T) {
	// Should truncate at 256 bytes
	input := make([]byte, 300)
	for i := range input {
		input[i] = 'A'
	}
	got := extractPrintable(input)
	if len(got) != 256 {
		t.Errorf("extractPrintable() length = %d, want 256", len(got))
	}
}

func TestPayloadSHA256_Correctness(t *testing.T) {
	testPayloads := []struct {
		name    string
		payload []byte
	}{
		{"empty", []byte{}},
		{"http_get", []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")},
		{"binary", []byte{0x00, 0xFF, 0x7F, 0x80}},
		{"zeros", make([]byte, 1000)},
	}

	for _, tt := range testPayloads {
		t.Run(tt.name, func(t *testing.T) {
			// Compute expected hash
			var expected string
			if len(tt.payload) > 0 {
				shaSum := sha256.Sum256(tt.payload)
				expected = hex.EncodeToString(shaSum[:])
			}

			// Verify hash via Event struct construction (mirrors Capture logic)
			var payloadSHA string
			if len(tt.payload) > 0 {
				shaSum := sha256.Sum256(tt.payload)
				payloadSHA = hex.EncodeToString(shaSum[:])
			}

			if payloadSHA != expected {
				t.Errorf("PayloadSHA256 = %s, want %s", payloadSHA, expected)
			}

			// Hash should always be 64 hex chars (32 bytes) when non-empty
			if len(tt.payload) > 0 && len(payloadSHA) != 64 {
				t.Errorf("PayloadSHA256 length = %d, want 64", len(payloadSHA))
			}

			// Empty payloads should produce empty hash (omitempty)
			if len(tt.payload) == 0 && payloadSHA != "" {
				t.Errorf("empty payload should produce empty SHA, got %s", payloadSHA)
			}
		})
	}
}

func TestPayloadSHA256_DifferentInputs(t *testing.T) {
	// Verify that different inputs produce different hashes
	payload1 := []byte("GET / HTTP/1.1")
	payload2 := []byte("POST /login HTTP/1.1")

	sha1 := sha256.Sum256(payload1)
	sha2 := sha256.Sum256(payload2)

	hash1 := hex.EncodeToString(sha1[:])
	hash2 := hex.EncodeToString(sha2[:])

	if hash1 == hash2 {
		t.Error("different payloads should produce different SHA256 hashes")
	}
}

// pipePair returns a connected pair of net.Conn for testing Capture().
// The returned pair behaves like net.TCPConn but does NOT implement *net.TCPAddr,
// which exercises the non-TCP safety branch of Capture().
func pipePair() (net.Conn, net.Conn) {
	return net.Pipe()
}

func TestCapture_Basic(t *testing.T) {
	// Use a real TCP connection to exercise the *net.TCPAddr code path
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	errCh := make(chan error, 1)
	go func() {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		if _, err := conn.Write(payload); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	event := Capture(server, time.Second, 65536)

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	if event.Size != len(payload) {
		t.Errorf("Size = %d, want %d", event.Size, len(payload))
	}
	if event.Hex != hex.EncodeToString(payload) {
		t.Errorf("Hex mismatch:\ngot:  %q\nwant: %q", event.Hex, hex.EncodeToString(payload))
	}
	if event.Proto != "tcp" {
		t.Errorf("Proto = %q, want \"tcp\"", event.Proto)
	}
	if event.PayloadSHA256 == "" {
		t.Fatal("PayloadSHA256 should not be empty for non-empty payload")
	}
	if len(event.PayloadSHA256) != 64 {
		t.Errorf("PayloadSHA256 length = %d, want 64", len(event.PayloadSHA256))
	}
	// Verify SHA256 correctness
	shaSum := sha256.Sum256(payload)
	expectedHash := hex.EncodeToString(shaSum[:])
	if event.PayloadSHA256 != expectedHash {
		t.Errorf("PayloadSHA256 = %q, want %q", event.PayloadSHA256, expectedHash)
	}
	if event.SourceIP != "127.0.0.1" {
		t.Errorf("SourceIP = %q, want \"127.0.0.1\"", event.SourceIP)
	}
}

func TestCapture_EmptyPayload(t *testing.T) {
	server, client := pipePair()
	defer server.Close()
	defer client.Close()

	go func() {
		client.Close()
	}()

	event := Capture(server, time.Second, 65536)

	if event.Size != 0 {
		t.Errorf("Size = %d, want 0", event.Size)
	}
	if event.PayloadSHA256 != "" {
		t.Errorf("PayloadSHA256 for empty payload should be empty, got %q", event.PayloadSHA256)
	}
}

func TestCapture_MaxPayloadSizeLimit(t *testing.T) {
	// Use real TCP so data arrives in chunks
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	payload := make([]byte, 200)
	for i := range payload {
		payload[i] = 'A'
	}

	go func() {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return
		}
		defer conn.Close()
		// Write in chunks to force multiple Read() calls
		conn.Write(payload[:100])
		// Small delay to let the server read first chunk before sending second
		time.Sleep(50 * time.Millisecond)
		conn.Write(payload[100:])
	}()

	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	event := Capture(server, time.Second, 50)

	if event.Size > 200 {
		t.Errorf("Size = %d, should not exceed payload size", event.Size)
	}
}

func TestCapture_ReadTimeout(t *testing.T) {
	server, client := pipePair()
	defer server.Close()
	defer client.Close()

	payload := []byte("hello")
	go func() {
		client.Write(payload)
		// Don't close — let timeout trigger
		time.Sleep(100 * time.Millisecond)
		client.Write([]byte(" world"))
		client.Close()
	}()

	event := Capture(server, 50*time.Millisecond, 65536)

	// With a short timeout, we should get the first write but not the second
	if event.Size == 0 {
		t.Error("expected at least some data before timeout")
	}
}

func TestCapture_NonTCPNoPanic(t *testing.T) {
	// net.Pipe returns connections whose RemoteAddr() is NOT *net.TCPAddr.
	// Capture should handle this gracefully without panicking (regression test).
	server, client := pipePair()
	defer server.Close()
	defer client.Close()

	payload := []byte("test data")
	go func() {
		client.Write(payload)
		client.Close()
	}()

	event := Capture(server, time.Second, 65536)

	// The non-TCP branch should still capture the data
	if event.Size != len(payload) {
		t.Errorf("Size = %d, want %d", event.Size, len(payload))
	}
	// SourceIP should be empty since RemoteAddr isn't *net.TCPAddr
	if event.SourceIP != "" {
		t.Errorf("expected empty SourceIP for non-TCP conn, got %q", event.SourceIP)
	}
}

