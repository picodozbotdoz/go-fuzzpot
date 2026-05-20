package config

import (
        "fmt"
        "os"
        "time"

        "gopkg.in/yaml.v3"
)

type Config struct {
        Ports    PortsConfig    `yaml:"ports"`
        Capture  CaptureConfig  `yaml:"capture"`
        Logging  LoggingConfig  `yaml:"logging"`
        Refresh  RefreshConfig  `yaml:"refresh"`
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
        ReadTimeoutSec int `yaml:"read_timeout_sec"`
        MaxPayloadSize int `yaml:"max_payload_size"`
}

type LoggingConfig struct {
        Dir  string `yaml:"dir"`
        File string `yaml:"file"`
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
                },
                Logging: LoggingConfig{
                        Dir:  "/var/log/fuzzpot",
                        File: "payloads.log",
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

func (c *Config) Validate() error {
        for _, r := range c.Ports.Ranges {
                if r.From < 1 || r.To > 65535 || r.From > r.To {
                        return fmt.Errorf("invalid port range: %d-%d", r.From, r.To)
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
        return nil
}

func (c *Config) ReadTimeout() time.Duration {
        return time.Duration(c.Capture.ReadTimeoutSec) * time.Second
}

func (c *Config) RefreshInterval() time.Duration {
        return time.Duration(c.Refresh.IntervalSec) * time.Second
}

func (c *Config) LogPath() string {
        return c.Logging.Dir + "/" + c.Logging.File
}
