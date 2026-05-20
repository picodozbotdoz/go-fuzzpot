package capture

import (
        "encoding/hex"
        "encoding/json"
        "fmt"
        "net"
        "time"
)

// Event represents a single captured payload from an attacker.
type Event struct {
        Timestamp time.Time `json:"timestamp"`
        SourceIP  string    `json:"source_ip"`
        SourcePort int      `json:"source_port"`
        DestPort  int       `json:"dest_port"`
        Proto     string    `json:"proto"`     // "tcp"
        Size      int       `json:"size"`      // bytes received
        Hex       string    `json:"hex"`       // hex dump of payload
        Printable string    `json:"printable"` // printable ASCII portion
        Raw       []byte    `json:"-"`
}

func (e Event) String() string {
        return fmt.Sprintf(
                "[%s] %s:%d → :%d (%s) %d bytes → %s",
                e.Timestamp.Format("2006-01-02 15:04:05.000"),
                e.SourceIP, e.SourcePort, e.DestPort,
                e.Proto, e.Size, e.Printable,
        )
}

// JSONLine returns the event as a compact JSON line for log files.
func (e Event) JSONLine() string {
        b, _ := json.Marshal(e)
        return string(b)
}

// Capture reads from the connection until timeout or buffer full.
func Capture(conn net.Conn, timeout time.Duration, maxLen int) Event {
        var buf []byte

        conn.SetReadDeadline(time.Now().Add(timeout))
        tmp := make([]byte, 4096)

        for len(buf) < maxLen {
                n, err := conn.Read(tmp)
                if n > 0 {
                        buf = append(buf, tmp[:n]...)
                }
                if err != nil {
                        break // timeout, connection closed, or error
                }
        }

        remote, ok := conn.RemoteAddr().(*net.TCPAddr)
        if !ok {
                // Safety: if RemoteAddr is not *net.TCPAddr (e.g. wrapped conn),
                // return an empty event rather than panicking.
                return Event{
                        Timestamp: time.Now(),
                        Proto:     "tcp",
                        Size:      len(buf),
                        Hex:       hex.EncodeToString(buf),
                        Printable: extractPrintable(buf),
                        Raw:       buf,
                }
        }

        return Event{
                Timestamp:  time.Now(),
                SourceIP:   remote.IP.String(),
                SourcePort: remote.Port,
                Proto:      "tcp",
                Size:       len(buf),
                Hex:        hex.EncodeToString(buf),
                Printable:  extractPrintable(buf),
                Raw:        buf,
        }
}

func extractPrintable(data []byte) string {
        var b []byte
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
