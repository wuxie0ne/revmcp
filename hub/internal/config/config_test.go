package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigLoadWithCustomTunnelListen(t *testing.T) {
	t.Parallel()

	yamlData := `
listen: "127.0.0.1:8443"
tunnel_listen: "0.0.0.0:9443"
agent_signing_secret: "secret-key-for-unit-test-1234"
audit_log_path: "-"
clients:
  - name: "ops"
    token_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    scopes: ["read"]
    allowed_targets: ["*"]
`
	p := filepath.Join(t.TempDir(), "hub.yaml")
	if err := os.WriteFile(p, []byte(yamlData), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Listen != "127.0.0.1:8443" {
		t.Fatalf("unexpected listen: %q", cfg.Listen)
	}
	if cfg.TunnelListen != "0.0.0.0:9443" {
		t.Fatalf("unexpected tunnel_listen: %q", cfg.TunnelListen)
	}
}

func TestManagedChannelPolicyAndManagementURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.yaml")
	t.Setenv("TEST_REVMCP_MANAGEMENT_URL", "http://127.0.0.1:40051/")
	raw := []byte(`
agent_signing_secret: "agent-key-for-test-config"
management:
  hub_url: "${TEST_REVMCP_MANAGEMENT_URL}"
  admin_client: operator
tokens:
  mcp_signing_secret: "mcp-key-for-test-config"
  state_path: ./state.json
  defaults:
    agent_mode: restricted
    agent_ttl: 2h
    mcp_ttl: 24h
  profiles:
    fleet:
      target: "node-*"
      agent_ttl: 30m
clients:
  - name: operator
    token_sha256: "0000000000000000000000000000000000000000000000000000000000000000"
    scopes: ["admin"]
    allowed_targets: ["*"]
`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := cfg.Tokens.Resolve("fleet", IssuePolicy{Target: "node-1", MCPTTL: time.Hour})
	if err != nil || resolved.Target != "node-1" || resolved.Mode != "restricted" ||
		resolved.AgentTTL != 30*time.Minute || resolved.MCPTTL != time.Hour {
		t.Fatalf("wrong precedence for defaults, profile and explicit values: %+v, %v", resolved, err)
	}
	if base, err := LoadManagementURL(path); err != nil || base != "http://127.0.0.1:40051" {
		t.Fatalf("unexpected management URL %q: %v", base, err)
	}
	cfg.Clients[0].Scopes = []string{"read"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("managed channel configuration accepted an administrator without admin scope")
	}
	cfg.Clients[0].Scopes = []string{"admin"}
	for _, invalidSecret := range []string{"short", cfg.AgentSigningSecret} {
		cfg.Tokens.SigningSecret = invalidSecret
		if err := cfg.Validate(); err == nil {
			t.Fatal("accepted an invalid MCP signing key")
		}
	}
}
