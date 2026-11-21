package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds the runtime configuration for revmcp-hub.
type Config struct {
	Listen              string           `yaml:"listen"`
	TunnelListen        string           `yaml:"tunnel_listen"`
	AgentSigningSecret  string           `yaml:"agent_signing_secret"`
	AuditLogPath        string           `yaml:"audit_log_path"`
	MaxInflightPerAgent int              `yaml:"max_inflight_per_agent"`
	RateLimitRPS        float64          `yaml:"rate_limit_rps"`
	RateLimitBurst      int              `yaml:"rate_limit_burst"`
	Tokens              ChannelsConfig   `yaml:"tokens"`
	Management          ManagementConfig `yaml:"management"`
}

// Load reads, expands environment variables in, and validates a YAML config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}
	expanded := os.ExpandEnv(string(raw))

	var cfg Config
	decoder := yaml.NewDecoder(strings.NewReader(expanded))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config: parse yaml: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg.resolveStatePath(path)
	return &cfg, nil
}

// Validate checks required fields and fails closed on misconfiguration.
func (c *Config) Validate() error {
	c.Listen = strings.TrimSpace(c.Listen)
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8443"
	}
	c.TunnelListen = strings.TrimSpace(c.TunnelListen)
	if len(strings.TrimSpace(c.AgentSigningSecret)) < 16 {
		return fmt.Errorf("config: agent_signing_secret must be at least 16 bytes")
	}
	if c.MaxInflightPerAgent <= 0 {
		c.MaxInflightPerAgent = 16
	}
	if c.RateLimitRPS < 0 {
		return fmt.Errorf("config: rate_limit_rps cannot be negative")
	}
	if c.RateLimitBurst < 0 {
		return fmt.Errorf("config: rate_limit_burst cannot be negative")
	}
	if c.RateLimitRPS > 0 && c.RateLimitBurst == 0 {
		c.RateLimitBurst = max(1, int(c.RateLimitRPS*2))
	}
	if strings.TrimSpace(c.AuditLogPath) == "" {
		c.AuditLogPath = "-"
	}

	return c.validateChannels()
}
