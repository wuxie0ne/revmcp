package config

import (
	"os"
	"path/filepath"
	"testing"
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
