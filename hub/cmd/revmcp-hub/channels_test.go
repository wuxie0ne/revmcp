package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/revmcp/revmcp/hub/internal/admin"
	"github.com/revmcp/revmcp/hub/internal/channel"
)

func TestChannelCLIRequests(t *testing.T) {
	const adminToken = "cli-admin-fixture"
	t.Setenv("REVMCP_ADMIN_TOKEN", adminToken)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+adminToken {
			t.Error("management request omitted its administrator credential")
		}
		switch r.Method + " " + r.URL.Path {
		case "POST /admin/channels":
			var payload admin.IssueChannel
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
			}
			if payload.Name != "one" || payload.Policy.Target != "node-1" ||
				payload.Policy.MCPTTL != 24*time.Hour || len(payload.Policy.MCPScopes) != 1 ||
				payload.Policy.MCPScopes[0] != "read" {
				t.Error("issue flags were not forwarded to the Hub")
			}
		case "GET /admin/channels", "GET /admin/channels/one",
			"POST /admin/channels/one/reveal", "POST /admin/channels/one/rotate/mcp",
			"POST /admin/channels/one/revoke/agent", "DELETE /admin/channels/one",
			"POST /admin/channels/one/targets/node-1/shutdown":
		default:
			t.Errorf("unexpected management request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		item := channel.Detail{Name: "one", Target: "node-1"}
		if r.Method == http.MethodGet && r.URL.Path == "/admin/channels" {
			_ = json.NewEncoder(w).Encode([]channel.Detail{item})
			return
		}
		_ = json.NewEncoder(w).Encode(item)
	}))
	defer server.Close()

	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte("management:\n  hub_url: "+server.URL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"issue", "--name", "one", "--allowed-target", "node-1", "--scope", "read", "--ttl", "24h"},
		{"list"},
		{"list", "--channel", "one", "--details"},
		{"list", "--channel", "one", "--show-secrets"},
		{"rotate", "--channel", "one", "--kind", "mcp"},
		{"revoke", "--channel", "one", "--kind", "agent"},
	} {
		if err := runToken(append(args, "--config", cfg)); err != nil {
			t.Fatal(err)
		}
	}
	if err := runTarget([]string{"kick", "--config", cfg, "--channel", "one", "--target", "node-1"}); err != nil {
		t.Fatal(err)
	}
	if err := runChannel([]string{"delete", "--config", cfg, "--name", "one"}); err != nil {
		t.Fatal(err)
	}
	if err := runToken([]string{"issue", "--config", cfg, "--name", "one", "--allowed-target", "node-1", "--ttl", "500ms"}); err == nil {
		t.Fatal("issue accepted a duration shorter than one second")
	}
	if count := requests.Load(); count != 8 {
		t.Fatalf("expected eight requests, got %d", count)
	}
}
