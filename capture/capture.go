package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

// Event represents a single captured payload from an attacker.
//
// The listener's port is not part of the event: capture is per-connection
// and the port arrives as a parameter where the LogEntry is built (G13
// removed the never-populated DestPort field).
type Event struct {
	Timestamp     time.Time `json:"timestamp"` // first byte received
	SourceIP      string    `json:"source_ip"`
	SourcePort    int       `json:"source_port"`
	Proto         string    `json:"proto"`                    // "tcp"
	Size          int       `json:"size"`                     // bytes received
	Hex           string    `json:"hex"`                      // hex dump of payload
	Printable     string    `json:"printable"`                // printable ASCII portion
	PayloadSHA256 string    `json:"payload_sha256,omitempty"` // SHA256 hash for threat intel
	Truncated     bool      `json:"truncated,omitempty"`      // stopped at maxLen (G5)
	Raw           []byte    `json:"-"`
}

func (e Event) String() string {
	return fmt.Sprintf(
		"[%s] %s:%d (%s) %d bytes → %s",
		e.Timestamp.Format("2006-01-02 15:04:05.000"),
		e.SourceIP, e.SourcePort,
		e.Proto, e.Size, e.Printable,
	)
}

// Capture reads from the connection until timeout or buffer full.
//
// G5: Size never exceeds maxLen — each read takes min(remaining, chunk)
// bytes. When the cap stops the loop, Truncated is set; a payload that
// happened to be exactly maxLen bytes is conservatively reported as
// truncated too (a probe read would burn the rest of the deadline).
//
// G6: Timestamp is the time the first byte arrived, not capture
// completion — a slow-drip sender no longer skews ordering and the
// analyzer's rate windows by up to the whole timeout.
func Capture(conn net.Conn, timeout time.Duration, maxLen int) Event {
	var buf []byte
	start := time.Now()
	firstByte := time.Time{}

	conn.SetReadDeadline(start.Add(timeout))
	tmp := make([]byte, 4096)

	for len(buf) < maxLen {
		remaining := maxLen - len(buf)
		if remaining < len(tmp) {
			tmp = tmp[:remaining]
		}
		n, err := conn.Read(tmp)
		if n > 0 {
			if firstByte.IsZero() {
				firstByte = time.Now()
			}
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break // timeout, connection closed, or error
		}
	}
	truncated := len(buf) >= maxLen && maxLen > 0
	ts := firstByte
	if ts.IsZero() {
		ts = start // zero-byte event: fall back to capture start
	}

	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		// Safety: if RemoteAddr is not *net.TCPAddr (e.g. wrapped conn),
		// return an empty event rather than panicking.
		return Event{
			Timestamp: ts,
			Proto:     "tcp",
			Size:      len(buf),
			Hex:       hex.EncodeToString(buf),
			Printable: extractPrintable(buf),
			Truncated: truncated,
			Raw:       buf,
		}
	}

	// Compute SHA256 of payload for threat intel deduplication and IOC sharing
	var payloadSHA string
	if len(buf) > 0 {
		shaSum := sha256.Sum256(buf)
		payloadSHA = hex.EncodeToString(shaSum[:])
	}

	return Event{
		Timestamp:     ts,
		SourceIP:      remote.IP.String(),
		SourcePort:    remote.Port,
		Proto:         "tcp",
		Size:          len(buf),
		Hex:           hex.EncodeToString(buf),
		Printable:     extractPrintable(buf),
		PayloadSHA256: payloadSHA,
		Truncated:     truncated,
		Raw:           buf,
	}
}

func extractPrintable(data []byte) string {
	cap_ := len(data)
	if cap_ > 256 {
		cap_ = 256
	}
	b := make([]byte, 0, cap_)
	for _, c := range data {
		if c >= 32 && c <= 126 {
			b = append(b, c)
		} else if c == '\n' || c == '\r' || c == '\t' {
			b = append(b, c)
		} else {
			b = append(b, '.')
		}
		if len(b) >= 256 {
			break
		}
	}
	return string(b)
}
