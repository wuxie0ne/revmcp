package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/revmcp/revmcp/hub/internal/admin"
	hubauth "github.com/revmcp/revmcp/hub/internal/auth"
	"github.com/revmcp/revmcp/hub/internal/channel"
	"github.com/revmcp/revmcp/hub/internal/config"
	"github.com/revmcp/revmcp/hub/internal/mcpserver"
	"github.com/revmcp/revmcp/hub/internal/policy"
	"github.com/revmcp/revmcp/hub/internal/registry"
	"github.com/revmcp/revmcp/hub/internal/tunnel"
)

func TestManagedChannelLifecycle(t *testing.T) {
	agentBin := os.Getenv("REVMCP_AGENT_BIN")
	if agentBin == "" {
		t.Skip("run make test-e2e with the current Agent binary")
	}
	const adminToken = "test-managed-admin-token"
	const otherAdmin = "test-nondesignated-admin-token"
	const agentKey = "test-managed-agent-secret"
	sum := sha256.Sum256([]byte(adminToken))
	otherSum := sha256.Sum256([]byte(otherAdmin))
	cfg := &config.Config{
		Management: config.ManagementConfig{AdminClient: "issuer"},
		Tokens:     &config.ChannelsConfig{},
		Clients: []config.ClientConfig{{
			Name: "issuer", TokenSHA256: hex.EncodeToString(sum[:]), Scopes: []string{"admin"}, AllowedTargets: []string{"*"},
		}, {
			Name: "other", TokenSHA256: hex.EncodeToString(otherSum[:]), Scopes: []string{"admin"}, AllowedTargets: []string{"*"},
		}},
	}
	store, err := channel.Open(filepath.Join(t.TempDir(), "channels.json"), agentKey, "test-managed-mcp-secret", false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	static, err := hubauth.NewStaticBearerVerifier(cfg.Clients)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := hubauth.NewEnrollmentSigner(agentKey)
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.New()
	var auditLog syncBuffer
	audit := policy.NewAuditLoggerWithWriter(&auditLog)
	tunnelServer := tunnel.NewServer(legacy, reg, audit, "test", 8, nil)
	tunnelServer.UseChannels(store)
	mux := http.NewServeMux()
	mux.Handle("/agent/ws", tunnelServer)
	mcpserver.NewGateway("test", reg, audit).RegisterRoutes(mux, hubauth.WithChannelBearer(store, static))
	admin.NewHandler(reg, legacy, audit).RegisterChannelRoutes(mux, static, cfg, store)
	server := httptest.NewServer(mux)
	defer server.Close()

	api := func(method, endpoint, bearer string, body any, wantStatus int, dst any) {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, method, server.URL+endpoint, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode != wantStatus {
			t.Fatalf("%s %s: got %d, want %d", method, endpoint, response.StatusCode, wantStatus)
		}
		if dst != nil {
			if response.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("missing no-store on channel management response")
			}
			if err := json.NewDecoder(response.Body).Decode(dst); err != nil {
				t.Fatal(err)
			}
		} else {
			_, _ = io.Copy(io.Discard, response.Body)
		}
	}
	adminAPI := func(method, endpoint string, body any, status int, dst any) {
		t.Helper()
		api(method, "/admin/channels"+endpoint, adminToken, body, status, dst)
	}
	var a, b channel.Detail
	issue := admin.IssueChannel{Name: "a", Policy: config.IssuePolicy{Target: "node-*"}}
	adminAPI(http.MethodPost, "", issue, http.StatusCreated, &a)
	adminAPI(http.MethodPost, "", issue, http.StatusConflict, nil)
	issue.Name = "b"
	adminAPI(http.MethodPost, "", issue, http.StatusCreated, &b)
	api(http.MethodPost, "/admin/channels/a/reveal", a.Bearer, nil, http.StatusUnauthorized, nil)
	api(http.MethodGet, "/admin/channels", otherAdmin, nil, http.StatusForbidden, nil)
	api(http.MethodPost, "/admin/channels/a/reveal", otherAdmin, nil, http.StatusForbidden, nil)
	var revealed channel.Detail
	adminAPI(http.MethodPost, "/a/reveal", nil, http.StatusOK, &revealed)
	if revealed.Enrollment != a.Enrollment || revealed.Bearer != a.Bearer {
		t.Fatal("credential reveal returned different values")
	}

	start := func(value, tag, target string, flags ...string) *syncBuffer {
		t.Helper()
		args := []string{"--hub", "ws" + strings.TrimPrefix(server.URL, "http") + "/agent/ws", "--tag", "marker=" + tag}
		if target != "" {
			args = append(args, "--target-id", target)
		}
		command := exec.Command(agentBin, append(args, flags...)...)
		command.Env = append(os.Environ(), "REVMCP_ENROLL_TOKEN="+value)
		log := &syncBuffer{}
		command.Stderr = log
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = command.Process.Kill()
			_ = command.Wait()
		})
		return log
	}
	eventually := func(ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !ok() {
			if time.Now().After(deadline) {
				t.Fatal("timed out waiting for channel state")
			}
			time.Sleep(15 * time.Millisecond)
		}
	}
	idA, _ := store.ID("a")
	idB, _ := store.ID("b")
	start(a.Enrollment, "channel-a-marker", "node-1")
	start(a.Enrollment, "other", "node-2")
	start(b.Enrollment, "channel-b-marker", "node-1")
	eventually(func() bool {
		return len(reg.ListIn(idA, "", "")) == 2 && len(reg.ListIn(idB, "", "")) == 1
	})
	dupe := start(a.Enrollment, "duplicate", "node-1")
	implicit := start(a.Enrollment, "implicit", "")
	wrongTarget := start(a.Enrollment, "mismatch", "outside-rule")
	wrongMode := start(a.Enrollment, "wrong-mode", "node-3", "--mode", "restricted")
	eventually(func() bool {
		return strings.Contains(dupe.String(), "target already connected") &&
			strings.Contains(implicit.String(), "explicit target ID matching") &&
			strings.Contains(wrongTarget.String(), "explicit target ID matching") &&
			strings.Contains(wrongMode.String(), "mode exceeds channel maximum")
	})
	if entry, _ := reg.GetIn(idA, "node-1"); entry == nil || entry.Info.Tags["marker"] != "channel-a-marker" {
		t.Fatal("duplicate Agent evicted the existing connection")
	}
	var listing []channel.Detail
	adminAPI(http.MethodGet, "", nil, http.StatusOK, &listing)
	if len(listing) != 2 || len(listing[0].Targets) != 2 || len(listing[1].Targets) != 1 ||
		listing[0].Enrollment != "" || listing[0].Bearer != "" {
		t.Fatal("channel summary omitted online targets or exposed credentials")
	}

	call := func(path, bearer, tool string, args map[string]any) (int, string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return mcpCall(t, ctx, server.URL+path, bearer, map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": tool, "arguments": args},
		})
	}
	status, result := call("/mcp", a.Bearer, "list_targets", map[string]any{})
	if status != http.StatusOK || !strings.Contains(result, "channel-a-marker") || strings.Contains(result, "channel-b-marker") {
		t.Fatal("aggregate discovery crossed channels")
	}
	status, result = call("/mcp/node-2", b.Bearer, "get_system_info", map[string]any{})
	if status != http.StatusOK || !strings.Contains(result, "offline") {
		t.Fatal("single-target endpoint crossed channels")
	}
	var detail channel.Detail
	adminAPI(http.MethodGet, "/a", nil, http.StatusOK, &detail)
	if detail.Name != "a" || detail.Enrollment != "" || detail.Bearer != "" {
		t.Fatal("single-channel response did not return a metadata object")
	}
	var rotated channel.Detail
	adminAPI(http.MethodPost, "/a/rotate/mcp", nil, http.StatusOK, &rotated)
	if rotated.Bearer == "" || rotated.Bearer == a.Bearer {
		t.Fatal("rotation did not issue a new Bearer")
	}
	if code, _ := call("/mcp", a.Bearer, "list_targets", map[string]any{}); code != http.StatusUnauthorized {
		t.Fatal("rotated Bearer remained valid")
	}
	if code, _ := call("/mcp", rotated.Bearer, "list_targets", map[string]any{}); code != http.StatusOK {
		t.Fatal("replacement Bearer was rejected")
	}
	adminAPI(http.MethodPost, "/a/targets/node-1/shutdown", admin.ShutdownPayload{}, http.StatusOK, nil)
	eventually(func() bool {
		entry, ok := reg.GetIn(idA, "node-1")
		return ok && entry.Info.Tags["marker"] == "duplicate"
	})
	if entry, _ := reg.GetIn(idB, "node-1"); entry == nil || entry.Info.Tags["marker"] != "channel-b-marker" {
		t.Fatal("kick affected another channel")
	}
	adminAPI(http.MethodPost, "/a/revoke/mcp", nil, http.StatusOK, nil)
	if code, _ := call("/mcp", rotated.Bearer, "list_targets", map[string]any{}); code != http.StatusUnauthorized {
		t.Fatal("revoked Bearer remained valid")
	}
	adminAPI(http.MethodDelete, "/a", nil, http.StatusOK, nil)
	if len(reg.ListIn(idA, "", "")) != 0 || len(reg.ListIn(idB, "", "")) != 1 {
		t.Fatal("delete did not detach exactly the named channel")
	}
	log := auditLog.String()
	seen := make(map[string]bool)
	for line := range strings.SplitSeq(log, "\n") {
		var event policy.AuditEntry
		if json.Unmarshal([]byte(line), &event) == nil && event.ChannelID == idA {
			seen[event.Tool+"/"+event.Decision] = true
		}
	}
	for _, want := range []string{
		"agent.register/allow", "agent.register/deny", "admin.channel.issue/allow", "admin.channel.reveal/allow",
		"admin.channel.rotate/allow", "admin.shutdown/allow", "admin.channel.delete/allow",
	} {
		if !seen[want] {
			t.Errorf("missing channel-scoped audit event %s", want)
		}
	}
	if strings.Contains(log, a.Enrollment) || strings.Contains(log, a.Bearer) || strings.Contains(log, rotated.Bearer) {
		t.Fatal("audit contains raw credentials")
	}
}
