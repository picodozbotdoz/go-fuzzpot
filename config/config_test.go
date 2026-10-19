package config

import (
	"os"
	"path/filepath"
	"strings"
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

func TestValidate_OverlappingRanges(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Ports.Ranges = []PortRange{{From: 1000, To: 2000}, {From: 1500, To: 2500}}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Errorf("expected overlap error, got: %v", err)
	}
}

func TestValidate_DuplicateRanges(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Ports.Ranges = []PortRange{{From: 1000, To: 2000}, {From: 1000, To: 2000}}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Errorf("expected overlap error for duplicate ranges, got: %v", err)
	}
}

func TestValidate_AdjacentRangesValid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Ports.Ranges = []PortRange{{From: 1000, To: 2000}, {From: 2001, To: 3000}}
	if err := cfg.Validate(); err != nil {
		t.Errorf("adjacent ranges should be valid, got: %v", err)
	}
}

func TestExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	if Exists(path) {
		t.Error("Exists() should be false for a missing file")
	}
	if err := os.WriteFile(path, []byte("ports: {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !Exists(path) {
		t.Error("Exists() should be true after the file is created")
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
	want := filepath.Join("/var/log/fuzzpot", "payloads.log")
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

// ── G11: strict parsing and path/payload validation ────────────────────────

// A misspelled key must fail the load instead of silently falling back to
// its default.
func TestLoadRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(path, []byte("capture:\n  read_timeout_sek: 5\n"), 0640); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load accepted a misspelled key (G11)")
	}
	if !strings.Contains(err.Error(), "read_timeout_sek") {
		t.Fatalf("error should name the unknown field, got: %v", err)
	}
}

func TestValidateRejectsOversizePayload(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Capture.MaxPayloadSize = 1<<20 + 1
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted max_payload_size over 1 MiB (G11)")
	}
	cfg.Capture.MaxPayloadSize = 1 << 20
	if err := cfg.Validate(); err != nil {
		t.Fatalf("1 MiB boundary must be accepted, got: %v", err)
	}
}

func TestValidateRejectsRelativeLogDir(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Logging.Dir = "relative/logs"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted a relative logging.dir (G11)")
	}
}

func TestValidateRejectsFileWithPathSeparators(t *testing.T) {
	for _, name := range []string{"../escape.log", "sub/payloads.log", `sub\payloads.log`, "..", "."} {
		cfg := DefaultConfig()
		cfg.Logging.File = name
		if err := cfg.Validate(); err == nil {
			t.Fatalf("Validate accepted logging.file %q (G11)", name)
		}
	}
}

// ── R2-G4 / R2-G10 ────────────────────────────────────────────────────────

// An explicit zero used to silently disable the memory budget and fairness
// caps, contradicting the documented "zero falls back to defaults".
func TestLoadCoercesZeroLimitsToDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	yaml := "limits:\n  memory_budget_mb: 0\n  max_concurrent_per_port: 0\n  max_concurrent_per_ip: 0\n"
	if err := os.WriteFile(path, []byte(yaml), 0640); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	def := DefaultConfig()
	if cfg.Limits.MemoryBudgetMB != def.Limits.MemoryBudgetMB ||
		cfg.Limits.MaxPerPort != def.Limits.MaxPerPort ||
		cfg.Limits.MaxPerIP != def.Limits.MaxPerIP {
		t.Fatalf("explicit zeros not coerced to defaults: %+v", cfg.Limits)
	}
}

// An empty config file is "no config": defaults, not a parse failure.
func TestLoadEmptyFileUsesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(path, nil, 0640); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("empty config failed to load (R2-G10): %v", err)
	}
	if cfg.Capture.ReadTimeoutSec != 10 {
		t.Errorf("defaults not applied for empty config: %+v", cfg.Capture)
	}
}

// A2-12: sensor.name defaults to the hostname, an explicit empty value
// falls back the same way, and a set value is kept (trimmed).
func TestSensorNameDefaultsAndOverride(t *testing.T) {
	def := DefaultConfig()
	if def.Sensor.Name == "" {
		t.Fatal("DefaultConfig sensor name is empty; v3 lines must carry a sensor")
	}
	if h, err := os.Hostname(); err == nil && h != "" && def.Sensor.Name != h {
		t.Errorf("default sensor = %q, want hostname %q", def.Sensor.Name, h)
	}

	for _, tc := range []struct{ yaml, want string }{
		{"sensor:\n  name: \"\"\n", def.Sensor.Name},
		{"sensor:\n  name: \"  edge-sg-1 \"\n", "edge-sg-1"},
		{"refresh:\n  interval_sec: 60\n", def.Sensor.Name},
	} {
		path := filepath.Join(t.TempDir(), "cfg.yaml")
		if err := os.WriteFile(path, []byte(tc.yaml), 0640); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Sensor.Name != tc.want {
			t.Errorf("yaml %q: sensor = %q, want %q", tc.yaml, cfg.Sensor.Name, tc.want)
		}
	}
}

func TestValidateRejectsBadSensorName(t *testing.T) {
	for _, name := range []string{"has space", "tab\there", "nul\x00", "café", strings.Repeat("a", 254)} {
		cfg := DefaultConfig()
		cfg.Sensor.Name = name
		if err := cfg.Validate(); err == nil {
			t.Errorf("sensor.name %q accepted, want error", name)
		}
	}
	cfg := DefaultConfig()
	cfg.Sensor.Name = "edge-sg-1.example.net"
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid sensor.name rejected: %v", err)
	}
}
