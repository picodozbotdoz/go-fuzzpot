package config

import (
        "os"
        "path/filepath"
        "testing"
        "time"
)

func TestDefaultConfig(t *testing.T) {
        cfg := DefaultConfig()
        if len(cfg.Ports.Ranges) == 0 {
                t.Error("DefaultConfig() should have port ranges")
        }
        if cfg.Capture.ReadTimeoutSec != 10 {
                t.Errorf("Default ReadTimeoutSec = %d, want 10", cfg.Capture.ReadTimeoutSec)
        }
        if cfg.Capture.MaxPayloadSize != 65536 {
                t.Errorf("Default MaxPayloadSize = %d, want 65536", cfg.Capture.MaxPayloadSize)
        }
        if !cfg.Capture.LogHexPayload {
                t.Error("Default LogHexPayload should be true")
        }
        if cfg.Refresh.IntervalSec != 60 {
                t.Errorf("Default RefreshInterval = %d, want 60", cfg.Refresh.IntervalSec)
        }
        if cfg.Logging.RotateMB != 50 {
                t.Errorf("Default RotateMB = %d, want 50", cfg.Logging.RotateMB)
        }
        if cfg.Logging.KeepFiles != 10 {
                t.Errorf("Default KeepFiles = %d, want 10", cfg.Logging.KeepFiles)
        }
}

func TestValidate_Valid(t *testing.T) {
        cfg := DefaultConfig()
        if err := cfg.Validate(); err != nil {
                t.Errorf("Validate() on default config: %v", err)
        }
}

func TestValidate_InvalidPortRange(t *testing.T) {
        tests := []struct {
                name string
                from int
                to   int
        }{
                {"from_below_1", 0, 1000},
                {"to_above_65535", 1, 65536},
                {"from_greater_than_to", 5000, 1000},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        cfg := DefaultConfig()
                        cfg.Ports.Ranges = []PortRange{{From: tt.from, To: tt.to}}
                        if err := cfg.Validate(); err == nil {
                                t.Errorf("expected error for range %d-%d", tt.from, tt.to)
                        }
                })
        }
}

func TestValidate_ReadTimeoutTooLow(t *testing.T) {
        cfg := DefaultConfig()
        cfg.Capture.ReadTimeoutSec = 0
        if err := cfg.Validate(); err == nil {
                t.Error("expected error for ReadTimeoutSec=0")
        }
}

func TestValidate_MaxPayloadSizeZero(t *testing.T) {
        cfg := DefaultConfig()
        cfg.Capture.MaxPayloadSize = 0
        if err := cfg.Validate(); err == nil {
                t.Error("expected error for MaxPayloadSize=0 (would cause infinite loop)")
        }
}

func TestValidate_MaxPayloadSizeNegative(t *testing.T) {
        cfg := DefaultConfig()
        cfg.Capture.MaxPayloadSize = -1
        if err := cfg.Validate(); err == nil {
                t.Error("expected error for MaxPayloadSize=-1")
        }
}

func TestValidate_RefreshIntervalTooLow(t *testing.T) {
        cfg := DefaultConfig()
        cfg.Refresh.IntervalSec = 1
        if err := cfg.Validate(); err == nil {
                t.Error("expected error for IntervalSec=1")
        }
}

func TestValidate_RefreshIntervalBoundary(t *testing.T) {
        cfg := DefaultConfig()
        cfg.Refresh.IntervalSec = 5 // minimum allowed
        if err := cfg.Validate(); err != nil {
                t.Errorf("expected no error for IntervalSec=5, got: %v", err)
        }
}

func TestValidate_RotateMB_Invalid(t *testing.T) {
        cfg := DefaultConfig()
        cfg.Logging.RotateMB = 0
        if err := cfg.Validate(); err == nil {
                t.Error("expected error for RotateMB=0")
        }
}

func TestValidate_KeepFiles_Invalid(t *testing.T) {
        cfg := DefaultConfig()
        cfg.Logging.KeepFiles = -1
        if err := cfg.Validate(); err == nil {
                t.Error("expected error for KeepFiles=-1")
        }
}

func TestValidate_KeepFiles_Zero(t *testing.T) {
        cfg := DefaultConfig()
        cfg.Logging.KeepFiles = 0 // 0 = unlimited, should be valid
        if err := cfg.Validate(); err != nil {
                t.Errorf("expected no error for KeepFiles=0, got: %v", err)
        }
}

func TestLoad_FileNotExist(t *testing.T) {
        cfg, err := Load("/nonexistent/path.yaml")
        if err != nil {
                t.Fatalf("Load() on missing file: %v", err)
        }
        // Should return defaults
        if cfg.Capture.MaxPayloadSize != 65536 {
                t.Error("Load() from missing file should return defaults")
        }
}

func TestLoad_ValidYAML(t *testing.T) {
        dir := t.TempDir()
        path := filepath.Join(dir, "config.yaml")
        content := []byte(`
ports:
  ranges:
    - {from: 100, to: 200}
capture:
  read_timeout_sec: 5
  max_payload_size: 4096
refresh:
  interval_sec: 30
logging:
  dir: /tmp/logs
  file: test.log
`)
        if err := os.WriteFile(path, content, 0644); err != nil {
                t.Fatal(err)
        }
        cfg, err := Load(path)
        if err != nil {
                t.Fatalf("Load() error: %v", err)
        }
        if len(cfg.Ports.Ranges) != 1 || cfg.Ports.Ranges[0].From != 100 {
                t.Errorf("expected range 100-200, got %+v", cfg.Ports.Ranges)
        }
        if cfg.Capture.ReadTimeoutSec != 5 {
                t.Errorf("ReadTimeoutSec = %d, want 5", cfg.Capture.ReadTimeoutSec)
        }
        if cfg.Capture.MaxPayloadSize != 4096 {
                t.Errorf("MaxPayloadSize = %d, want 4096", cfg.Capture.MaxPayloadSize)
        }
        if cfg.Refresh.IntervalSec != 30 {
                t.Errorf("IntervalSec = %d, want 30", cfg.Refresh.IntervalSec)
        }
}

func TestLoad_BadYAML(t *testing.T) {
        dir := t.TempDir()
        path := filepath.Join(dir, "bad.yaml")
        if err := os.WriteFile(path, []byte("{{bad yaml}}"), 0644); err != nil {
                t.Fatal(err)
        }
        _, err := Load(path)
        if err == nil {
                t.Error("expected error for bad YAML")
        }
}

func TestLogPath(t *testing.T) {
        cfg := Config{
                Logging: LoggingConfig{Dir: "/var/log/fuzzpot", File: "payloads.log"},
        }
        want := "/var/log/fuzzpot/payloads.log"
        if got := cfg.LogPath(); got != want {
                t.Errorf("LogPath() = %q, want %q", got, want)
        }
}

func TestReadTimeout(t *testing.T) {
        cfg := Config{
                Capture: CaptureConfig{ReadTimeoutSec: 30},
        }
        want := 30 * time.Second
        if got := cfg.ReadTimeout(); got != want {
                t.Errorf("ReadTimeout() = %v, want %v", got, want)
        }
}

func TestRefreshInterval(t *testing.T) {
        cfg := Config{
                Refresh: RefreshConfig{IntervalSec: 120},
        }
        want := 120 * time.Second
        if got := cfg.RefreshInterval(); got != want {
                t.Errorf("RefreshInterval() = %v, want %v", got, want)
        }
}
