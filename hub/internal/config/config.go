package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds the runtime configuration for revmcp-hub.
type Config struct {
	Listen              string         `yaml:"listen"`
	TunnelListen        string         `yaml:"tunnel_listen"`
	AgentSigningSecret  string         `yaml:"agent_signing_secret"`
	AuditLogPath        string         `yaml:"audit_log_path"`
	MaxInflightPerAgent int            `yaml:"max_inflight_per_agent"`
	Clients             []ClientConfig `yaml:"clients"`
}

// ClientConfig defines an authorized northbound MCP API client.
type ClientConfig struct {
	Name           string   `yaml:"name"`
	TokenSHA256    string   `yaml:"token_sha256"`
	Scopes         []string `yaml:"scopes"`
	AllowedTargets []string `yaml:"allowed_targets"`
}

// Load reads, expands environment variables in, and validates a YAML config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}
	expanded := os.ExpandEnv(string(raw))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("config: parse yaml: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks required fields and fails closed on misconfiguration.
func (c *Config) Validate() error {
	c.Listen = strings.TrimSpace(c.Listen)
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8443"
	}
	c.TunnelListen = strings.TrimSpace(c.TunnelListen)
	if strings.TrimSpace(c.AgentSigningSecret) == "" {
		return fmt.Errorf("config: agent_signing_secret is required")
	}
	if c.MaxInflightPerAgent <= 0 {
		c.MaxInflightPerAgent = 16
	}
	if strings.TrimSpace(c.AuditLogPath) == "" {
		c.AuditLogPath = "-"
	}

	seenNames := make(map[string]bool, len(c.Clients))
	for i := range c.Clients {
		cl := &c.Clients[i]
		if strings.TrimSpace(cl.Name) == "" {
			return fmt.Errorf("config: client[%d] missing name", i)
		}
		if seenNames[cl.Name] {
			return fmt.Errorf("config: duplicate client name %q", cl.Name)
		}
		seenNames[cl.Name] = true

		cl.TokenSHA256 = strings.ToLower(strings.TrimSpace(cl.TokenSHA256))
		decoded, err := hex.DecodeString(cl.TokenSHA256)
		if err != nil || len(decoded) != 32 {
			return fmt.Errorf("config: client %q has invalid token_sha256 (must be 64 hex chars)", cl.Name)
		}
		if len(cl.Scopes) == 0 {
			return fmt.Errorf("config: client %q must define at least one scope", cl.Name)
		}
		if len(cl.AllowedTargets) == 0 {
			return fmt.Errorf("config: client %q must define at least one allowed_targets pattern", cl.Name)
		}
	}
	return nil
}
