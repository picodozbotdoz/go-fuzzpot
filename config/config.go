package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Ports   PortsConfig   `yaml:"ports"`
	Capture CaptureConfig `yaml:"capture"`
	Logging LoggingConfig `yaml:"logging"`
	Refresh RefreshConfig `yaml:"refresh"`
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

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
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
	return nil
}

func (c *Config) ReadTimeout() time.Duration {
	return time.Duration(c.Capture.ReadTimeoutSec) * time.Second
}

func (c *Config) RefreshInterval() time.Duration {
	return time.Duration(c.Refresh.IntervalSec) * time.Second
}

func (c *Config) LogPath() string {
	return filepath.Join(c.Logging.Dir, c.Logging.File)
}
