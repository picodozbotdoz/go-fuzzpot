package logger

import (
	"time"
)

// SecurityEventType enumerates the kinds of security-relevant events.
type SecurityEventType string

const (
	EventThrottled      SecurityEventType = "connection_throttled"
	EventConflictDetect SecurityEventType = "conflict_detected"
)

// SecurityEvent is a typed struct for security log serialization.
type SecurityEvent struct {
	EventType  SecurityEventType `json:"event_type"`
	Timestamp  string            `json:"ts"`
	RemoteAddr string            `json:"remote_addr,omitempty"`
	Port       int               `json:"port,omitempty"`
	Ports      []int             `json:"ports,omitempty"`
	Count      int               `json:"count,omitempty"`  // aggregate events (G7)
	Sensor     string            `json:"sensor,omitempty"` // instance identity (A2-12)
}

// SecurityLogger wraps Logger for security-relevant events.
// It writes to a separate security.log file for easier incident response monitoring.
type SecurityLogger struct {
	*Logger
	// Sensor is stamped on every event (A2-12); set it before the first write.
	Sensor string
}

// NewSecurityLogger creates a SecurityLogger that writes to security.log.
// Uses smaller rotation size (10MB) and keeps more files (30) for better audit trail.
func NewSecurityLogger(dir string) (*SecurityLogger, error) {
	log, err := New(dir, "security.log", 10, 30)
	if err != nil {
		return nil, err
	}
	return &SecurityLogger{Logger: log}, nil
}

// LogThrottled logs a connection throttling event when the connection limit is reached.
//
// Kept for low-rate, attributable rejections (tests, manual runs). The
// accept path must not call it: per-event I/O with attacker-controlled
// volume stalls the listener (G7) — use LogThrottledBulk from a reporter.
func (sl *SecurityLogger) LogThrottled(remoteAddr string, port int) {
	event := SecurityEvent{
		EventType:  EventThrottled,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		RemoteAddr: remoteAddr,
		Port:       port,
		Sensor:     sl.Sensor,
	}
	sl.WriteEventTyped(event)
}

// LogThrottledBulk records that count connections were rejected between
// reporter ticks. Aggregate-only on purpose: under flood the accept loop
// only increments a counter and this write happens off that path (G7).
func (sl *SecurityLogger) LogThrottledBulk(count int) {
	if count <= 0 {
		return
	}
	event := SecurityEvent{
		EventType: EventThrottled,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Count:     count,
		Sensor:    sl.Sensor,
	}
	sl.WriteEventTyped(event)
}

// LogConflict logs a port conflict detection event.
func (sl *SecurityLogger) LogConflict(ports []int) {
	event := SecurityEvent{
		EventType: EventConflictDetect,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Ports:     ports,
		Sensor:    sl.Sensor,
	}
	sl.WriteEventTyped(event)
}
