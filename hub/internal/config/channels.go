package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/revmcp/revmcp/hub/internal/channel"
	"github.com/revmcp/revmcp/proto"
	"gopkg.in/yaml.v3"
)

type ManagementConfig struct {
	HubURL           string `yaml:"hub_url"`
	AdminTokenSHA256 string `yaml:"admin_token_sha256"`
}

type ChannelsConfig struct {
	SigningSecret string                 `yaml:"mcp_signing_secret"`
	StatePath     string                 `yaml:"state_path"`
	Defaults      IssuePolicy            `yaml:"defaults"`
	Profiles      map[string]IssuePolicy `yaml:"profiles"`
}

type IssuePolicy struct {
	Target    string        `yaml:"target" json:"target,omitempty"`
	Mode      proto.Mode    `yaml:"agent_mode" json:"agent_mode,omitempty"`
	AgentTTL  time.Duration `yaml:"agent_ttl" json:"agent_ttl,omitempty"`
	MCPScopes []string      `yaml:"mcp_scopes" json:"mcp_scopes,omitempty"`
	MCPTTL    time.Duration `yaml:"mcp_ttl" json:"mcp_ttl,omitempty"`
}

func (c *ChannelsConfig) Resolve(profile string, overrides IssuePolicy) (channel.Policy, error) {
	policy := channel.Policy{
		Mode: proto.ModeReadOnly, AgentTTL: 2 * time.Hour,
		MCPScopes: []string{"read"}, MCPTTL: 24 * time.Hour,
	}
	applyIssuePolicy(&policy, c.Defaults)
	if profile != "" {
		proposed, ok := c.Profiles[profile]
		if !ok {
			return channel.Policy{}, fmt.Errorf("%w: unknown profile %q", channel.ErrInvalid, profile)
		}
		applyIssuePolicy(&policy, proposed)
	}
	applyIssuePolicy(&policy, overrides)
	return policy, policy.Validate()
}

func applyIssuePolicy(dst *channel.Policy, src IssuePolicy) {
	if src.Target != "" {
		dst.Target = src.Target
	}
	if src.Mode != "" {
		dst.Mode = src.Mode
	}
	if src.AgentTTL != 0 {
		dst.AgentTTL = src.AgentTTL
	}
	if src.MCPScopes != nil {
		dst.MCPScopes = src.MCPScopes
	}
	if src.MCPTTL != 0 {
		dst.MCPTTL = src.MCPTTL
	}
}

func (c *Config) validateChannels() error {
	if len(strings.TrimSpace(c.Tokens.SigningSecret)) < 16 || c.Tokens.SigningSecret == c.AgentSigningSecret ||
		strings.TrimSpace(c.Tokens.StatePath) == "" {
		return errors.New("config: tokens requires a state_path and a distinct mcp_signing_secret of at least 16 bytes")
	}
	for name := range c.Tokens.Profiles {
		if _, err := c.Tokens.Resolve(name, IssuePolicy{}); err != nil {
			return fmt.Errorf("config: profile %q: %w", name, err)
		}
	}
	if _, err := c.Tokens.Resolve("", IssuePolicy{Target: "validate-defaults"}); err != nil {
		return fmt.Errorf("config: token defaults: %w", err)
	}
	if _, err := ValidateHubURL(c.Management.HubURL); err != nil {
		return err
	}
	digest := strings.TrimSpace(c.Management.AdminTokenSHA256)
	if decoded, err := hex.DecodeString(digest); err != nil || len(decoded) != 32 {
		return errors.New("config: management.admin_token_sha256 must be 64 hex chars")
	}
	c.Management.AdminTokenSHA256 = digest
	return nil
}

func LoadManagementURL(configPath string) (string, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	var cfg struct {
		Management ManagementConfig `yaml:"management"`
	}
	if err := yaml.Unmarshal([]byte(os.ExpandEnv(string(raw))), &cfg); err != nil {
		return "", fmt.Errorf("parse management configuration: %w", err)
	}
	return ValidateHubURL(cfg.Management.HubURL)
}

func ValidateHubURL(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", errors.New("management.hub_url must be an HTTP(S) base URL")
	}
	return strings.TrimRight(value, "/"), nil
}

func (c *Config) resolveStatePath(configPath string) {
	if !filepath.IsAbs(c.Tokens.StatePath) {
		c.Tokens.StatePath = filepath.Join(filepath.Dir(configPath), c.Tokens.StatePath)
	}
}
