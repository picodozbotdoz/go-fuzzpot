package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Ports   PortsConfig   `yaml:"ports"`
	Capture CaptureConfig `yaml:"capture"`
	Logging LoggingConfig `yaml:"logging"`
	Refresh RefreshConfig `yaml:"refresh"`
	Limits  LimitsConfig  `yaml:"limits"`
	Stats   StatsConfig   `yaml:"stats"`
	Sensor  SensorConfig  `yaml:"sensor"`
}

// SensorConfig identifies this honeypot instance in every log line (A2-12),
// so one analyzer can ingest several sensors and still tell them apart.
type SensorConfig struct {
	// Name is the `sensor` value written to payload and security logs.
	// Empty (or absent) falls back to the hostname.
	Name string `yaml:"name"`
}

// maxSensorNameLen bounds the per-line cost of the identity field; it is
// the DNS name limit, so a hostname default always fits.
const maxSensorNameLen = 253

// defaultSensorName is the hostname, or "unknown" when the OS cannot
// report one — every v3 line must carry a non-empty sensor.
func defaultSensorName() string {
	if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
		return strings.TrimSpace(h)
	}
	return "unknown"
}

type StatsConfig struct {
	// IntervalSec is the stats/security-aggregate tick (G12). Ten seconds
	// matches the old hardcoded value.
	IntervalSec int `yaml:"interval_sec"`
}

type PortsConfig struct {
	Ranges  []PortRange `yaml:"ranges"`
	Exclude []int       `yaml:"exclude"`
}

type PortRange struct {
	From int `yaml:"from"`
	To   int `yaml:"to"`
}

type CaptureConfig struct {
	ReadTimeoutSec int  `yaml:"read_timeout_sec"`
	MaxPayloadSize int  `yaml:"max_payload_size"`
	LogHexPayload  bool `yaml:"log_hex_payload"`
}

type LoggingConfig struct {
	Dir       string `yaml:"dir"`
	File      string `yaml:"file"`
	RotateMB  int    `yaml:"rotate_mb"`
	KeepFiles int    `yaml:"keep_files"`
	// Compress gzips rotated files after CompressDelaySec, giving log
	// tailers a window to drain them while still plain text.
	Compress bool `yaml:"compress"`
	// CompressDelaySec delays compression of rotated files (default 60).
	CompressDelaySec int `yaml:"compress_delay_sec"`
	// FsyncWrites fsyncs after every event write (durable but slow).
	FsyncWrites bool `yaml:"fsync_writes"`
}

type RefreshConfig struct {
	IntervalSec int `yaml:"interval_sec"`
}

// LimitsConfig bounds the resources an attacker can make the sensor hold.
// Zero values fall back to the defaults set in DefaultConfig.
type LimitsConfig struct {
	// MemoryBudgetMB caps the estimated in-flight handler footprint (read
	// buffer + hex + JSON line). Slots are granted only while the estimate
	// fits, so the process stays below the systemd MemoryMax.
	MemoryBudgetMB int `yaml:"memory_budget_mb"`
	// MaxPerPort / MaxPerIP stop one flooded port or one sender from
	// occupying every slot.
	MaxPerPort int `yaml:"max_concurrent_per_port"`
	MaxPerIP   int `yaml:"max_concurrent_per_ip"`
}

func DefaultConfig() Config {
	return Config{
		Ports: PortsConfig{
			Ranges: []PortRange{
				{From: 2000, To: 5000},
				{From: 8000, To: 9000},
			},
			Exclude: []int{2222, 2223, 3306, 5432, 6379, 27017},
		},
		Capture: CaptureConfig{
			ReadTimeoutSec: 10,
			MaxPayloadSize: 65536,
			LogHexPayload:  true,
		},
		Logging: LoggingConfig{
			Dir:              "/var/log/fuzzpot",
			File:             "payloads.log",
			RotateMB:         50,
			KeepFiles:        10,
			Compress:         false,
			CompressDelaySec: 60,
			FsyncWrites:      false,
		},
		Refresh: RefreshConfig{
			IntervalSec: 60,
		},
		Limits: LimitsConfig{
			MemoryBudgetMB: 64,
			MaxPerPort:     64,
			MaxPerIP:       32,
		},
		Stats: StatsConfig{
			IntervalSec: 10,
		},
		Sensor: SensorConfig{
			Name: defaultSensorName(),
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	// KnownFields: a misspelled key must fail the load, not silently fall
	// back to its default (G11). Defaults still apply for absent keys.
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		// R2-G10: an empty config file is "no config", not a parse failure
		// — `touch config.yaml` used to abort startup with "parse config:
		// EOF".
		if errors.Is(err, io.EOF) {
			return &cfg, nil
		}
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// R2-G4: LimitsConfig documents "zero values fall back to the
	// defaults", but decoding an explicit 0 overwrites the seeded default
	// — silently disabling the memory budget and the fairness caps. Coerce
	// non-positive values back.
	def := DefaultConfig()
	if cfg.Limits.MemoryBudgetMB <= 0 {
		cfg.Limits.MemoryBudgetMB = def.Limits.MemoryBudgetMB
	}
	if cfg.Limits.MaxPerPort <= 0 {
		cfg.Limits.MaxPerPort = def.Limits.MaxPerPort
	}
	if cfg.Limits.MaxPerIP <= 0 {
		cfg.Limits.MaxPerIP = def.Limits.MaxPerIP
	}
	// A2-12: `name: ""` overwrites the seeded hostname the same way.
	cfg.Sensor.Name = strings.TrimSpace(cfg.Sensor.Name)
	if cfg.Sensor.Name == "" {
		cfg.Sensor.Name = def.Sensor.Name
	}

	return &cfg, nil
}

// Exists reports whether a config file is present at path. Callers use it
// to warn (or, in strict mode, fail) before Load falls back to defaults.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (c *Config) Validate() error {
	for _, r := range c.Ports.Ranges {
		if r.From < 1 || r.To > 65535 || r.From > r.To {
			return fmt.Errorf("invalid port range: %d-%d", r.From, r.To)
		}
	}
	// Overlapping (or duplicated) ranges are almost always a config
	// mistake; TargetPorts would silently dedup them.
	for i := 0; i < len(c.Ports.Ranges); i++ {
		for j := i + 1; j < len(c.Ports.Ranges); j++ {
			a, b := c.Ports.Ranges[i], c.Ports.Ranges[j]
			if a.From <= b.To && b.From <= a.To {
				return fmt.Errorf("port ranges overlap: %d-%d and %d-%d", a.From, a.To, b.From, b.To)
			}
		}
	}
	if c.Capture.ReadTimeoutSec < 1 {
		return fmt.Errorf("read_timeout_sec must be >= 1")
	}
	if c.Capture.MaxPayloadSize < 1 {
		return fmt.Errorf("max_payload_size must be >= 1")
	}
	// G11: each captured event costs ~8x max_payload_size in flight (buffer,
	// hex, JSON line) — a runaway value defeats the memory budget.
	if c.Capture.MaxPayloadSize > 1<<20 {
		return fmt.Errorf("max_payload_size must be <= %d (1 MiB)", 1<<20)
	}
	if c.Refresh.IntervalSec < 5 {
		return fmt.Errorf("refresh_interval_sec must be >= 5")
	}
	if c.Logging.RotateMB < 1 {
		return fmt.Errorf("rotate_mb must be >= 1")
	}
	if c.Logging.KeepFiles < 0 {
		return fmt.Errorf("keep_files must be >= 0")
	}
	if c.Logging.CompressDelaySec < 0 {
		return fmt.Errorf("compress_delay_sec must be >= 0")
	}
	// G11: the sensor writes as root-adjacent service accounts; a relative
	// dir or a file component would let a bad config point the payload log
	// anywhere on disk. Absolute under either convention: deployments use
	// POSIX paths even when validated on a Windows dev host.
	if !filepath.IsAbs(c.Logging.Dir) && !strings.HasPrefix(c.Logging.Dir, "/") {
		return fmt.Errorf("logging.dir must be an absolute path, got %q", c.Logging.Dir)
	}
	if c.Logging.File == "" || c.Logging.File == "." || c.Logging.File == ".." ||
		strings.ContainsAny(c.Logging.File, `/\`) {
		return fmt.Errorf("logging.file must be a bare file name, got %q", c.Logging.File)
	}
	// A2-12: the analyzer groups and filters by sensor, so keep it a short
	// printable token rather than free text.
	if len(c.Sensor.Name) > maxSensorNameLen {
		return fmt.Errorf("sensor.name must be at most %d bytes, got %d", maxSensorNameLen, len(c.Sensor.Name))
	}
	for _, r := range c.Sensor.Name {
		if r <= ' ' || r > '~' {
			return fmt.Errorf("sensor.name must be printable ASCII without spaces, got %q", c.Sensor.Name)
		}
	}
	return nil
}

func (c *Config) ReadTimeout() time.Duration {
	return time.Duration(c.Capture.ReadTimeoutSec) * time.Second
}

func (c *Config) RefreshInterval() time.Duration {
	return time.Duration(c.Refresh.IntervalSec) * time.Second
}

func (c *Config) StatsInterval() time.Duration {
	if c.Stats.IntervalSec <= 0 {
		return 10 * time.Second
	}
	return time.Duration(c.Stats.IntervalSec) * time.Second
}

func (c *Config) LogPath() string {
	return filepath.Join(c.Logging.Dir, c.Logging.File)
}
