package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	hubauth "github.com/revmcp/revmcp/hub/internal/auth"
	"github.com/revmcp/revmcp/hub/internal/channel"
	"github.com/revmcp/revmcp/hub/internal/policy"
	"github.com/revmcp/revmcp/hub/internal/registry"
	"github.com/revmcp/revmcp/proto"
)

type fakeCaller struct{}

func (f *fakeCaller) Call(_ context.Context, method string, _ any, dst any) error {
	if method == proto.MethodSysInfo {
		raw, _ := json.Marshal(proto.SysInfoResult{Hostname: "prod-web-01", Arch: "amd64", CPUCores: 4})
		return json.Unmarshal(raw, dst)
	}
	return nil
}

func (f *fakeCaller) Close() error { return nil }

func TestMCPBearerAuthAndListTargets(t *testing.T) {
	t.Parallel()

	store, credentials := issueMCPTestChannel(t, []string{policy.ScopeRead})
	rawToken := credentials.Bearer
	reg := registry.New()
	addTestTarget(t, reg, credentials.ChannelID, proto.AgentInfo{TargetID: "prod-web-01", Hostname: "prod-web-01", Mode: proto.ModeReadOnly})
	addTestTarget(t, reg, credentials.ChannelID, proto.AgentInfo{TargetID: "dev-box-01", Hostname: "dev-box-01", Mode: proto.ModeFull})

	var auditBuf bytes.Buffer
	gw := NewGateway("test", reg, policy.NewAuditLoggerWithWriter(&auditBuf))

	mux := http.NewServeMux()
	gw.RegisterRoutes(mux, hubauth.NewChannelBearerVerifier(store))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// 1. Unauthenticated request must return 401.
	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("unauthenticated request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", resp.StatusCode)
	}

	// 2. Authenticated tools/call for list_targets must return only allowed prod-* targets and log audit.
	callBody := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_targets","arguments":{}}}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/mcp", strings.NewReader(callBody))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("authenticated tools/call failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	var respBuf bytes.Buffer
	_, _ = respBuf.ReadFrom(resp.Body)
	body := respBuf.String()
	if !strings.Contains(body, "prod-web-01") {
		t.Fatalf("expected prod-web-01 in list_targets response, got: %s", body)
	}
	if strings.Contains(body, "dev-box-01") {
		t.Fatalf("dev-box-01 must be filtered out by allowed_targets, got: %s", body)
	}
	if !strings.Contains(auditBuf.String(), `"tool":"list_targets"`) || !strings.Contains(auditBuf.String(), `"decision":"allow"`) {
		t.Fatalf("expected JSONL audit entry for list_targets, got: %s", auditBuf.String())
	}

	// 3. Isolated endpoint /mcp/prod-web-01 must work and wrap output in <remote_output>.
	isoBody := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_system_info","arguments":{}}}`
	req2, err := http.NewRequest(http.MethodPost, ts.URL+"/mcp/prod-web-01", strings.NewReader(isoBody))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req2.Header.Set("Authorization", "Bearer "+rawToken)
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Accept", "application/json, text/event-stream")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("isolated tools/call failed: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()

	var resp2Buf bytes.Buffer
	_, _ = resp2Buf.ReadFrom(resp2.Body)
	if resp2.StatusCode != http.StatusOK || !strings.Contains(resp2Buf.String(), "remote_output") {
		t.Fatalf("expected wrapped remote_output from isolated endpoint, status=%d body=%s", resp2.StatusCode, resp2Buf.String())
	}
}

func postMCP(t *testing.T, url, token, payload string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(payload))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.String()
}

func TestMCPClientSessionRejectsCallsAfterBearerExpiry(t *testing.T) {
	t.Parallel()

	store, err := channel.Open(filepath.Join(t.TempDir(), "channels.json"), "test-mcpserver-agent-key", "test-mcpserver-mcp-key", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	credentials, err := store.Issue("expiry", channel.Policy{
		Target: "node-1", Mode: proto.ModeReadOnly, AgentTTL: time.Hour, MCPScopes: []string{policy.ScopeRead}, MCPTTL: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	audit := policy.NewAuditLoggerWithWriter(&bytes.Buffer{})
	NewGateway("test", registry.New(), audit).RegisterRoutes(mux, hubauth.NewChannelBearerVerifier(store))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+credentials.Bearer)
		mux.ServeHTTP(w, r)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "expiry-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: server.URL + "/mcp", DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()

	params := &mcp.CallToolParams{Name: "list_targets"}
	if result, err := session.CallTool(ctx, params); err != nil || result.IsError {
		t.Fatalf("valid Bearer should permit calls, got %v, %v", result, err)
	}

	time.Sleep(time.Until(credentials.MCPExpires))
	if _, err := session.CallTool(ctx, params); err == nil || !strings.Contains(err.Error(), http.StatusText(http.StatusUnauthorized)) {
		t.Fatalf("existing MCP client must receive HTTP 401 after Bearer expiry, got %v", err)
	}
}

func TestIsolatedSchemaDefenseInDepthAndRateLimit(t *testing.T) {
	t.Parallel()

	store, credentials := issueMCPTestChannel(t, []string{policy.ScopeRead, policy.ScopeExecRestricted, policy.ScopeExecSession})
	restrictedTok := credentials.Bearer
	reg := registry.New()
	addTestTarget(t, reg, credentials.ChannelID, proto.AgentInfo{TargetID: "prod-ro", Mode: proto.ModeReadOnly})
	addTestTarget(t, reg, credentials.ChannelID, proto.AgentInfo{TargetID: "prod-full", Mode: proto.ModeFull})
	addTestTarget(t, reg, credentials.ChannelID, proto.AgentInfo{TargetID: "dev-other", Mode: proto.ModeFull})

	var auditBuf bytes.Buffer
	gw := NewGateway("test", reg, policy.NewAuditLoggerWithWriter(&auditBuf))

	mux := http.NewServeMux()
	gw.RegisterRoutes(mux, hubauth.NewChannelBearerVerifier(store))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// 1. Isolated /mcp/prod-ro tools/list must omit target_id from tool input schemas.
	status, body := postMCP(t, ts.URL+"/mcp/prod-ro", restrictedTok, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if status != http.StatusOK {
		t.Fatalf("expected 200 on isolated tools/list, got %d: %s", status, body)
	}
	if strings.Contains(body, `"target_id"`) {
		t.Fatalf("isolated /mcp/{target_id} schema must hide target_id, got: %s", body)
	}

	// 2. Cross-target isolated call to dev-other must return tool error (isError:true) and deny audit.
	status, body = postMCP(t, ts.URL+"/mcp/dev-other", restrictedTok, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_system_info","arguments":{}}}`)
	if status != http.StatusOK || !strings.Contains(body, `"isError":true`) || !strings.Contains(body, "allowed_targets") {
		t.Fatalf("expected MCP tool error for unauthorized target, status=%d body=%s", status, body)
	}

	// 3. exec_command on full-mode target without exec:full scope must be denied.
	status, body = postMCP(t, ts.URL+"/mcp", restrictedTok, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"exec_command","arguments":{"target_id":"prod-full","command":"ls"}}}`)
	if status != http.StatusOK || !strings.Contains(body, `"isError":true`) || !strings.Contains(body, "exec:full") {
		t.Fatalf("expected exec:full denial on full-mode target, status=%d body=%s", status, body)
	}

	// 4. shell_session on readonly target must be denied at Hub.
	status, body = postMCP(t, ts.URL+"/mcp", restrictedTok, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shell_session","arguments":{"target_id":"prod-ro","action":"open"}}}`)
	if status != http.StatusOK || !strings.Contains(body, `"isError":true`) || !strings.Contains(body, "full mode") {
		t.Fatalf("expected full mode denial for shell_session on readonly target, status=%d body=%s", status, body)
	}

	// 5. Rate limiter blocks bursts above configured burst=1.
	gw.SetRateLimiter(policy.NewRateLimiter(0.1, 1))
	status, body = postMCP(t, ts.URL+"/mcp/prod-ro", restrictedTok, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_system_info","arguments":{}}}`)
	if status != http.StatusOK || strings.Contains(body, `"isError":true`) {
		t.Fatalf("expected first call within burst to succeed, status=%d body=%s", status, body)
	}
	status, body = postMCP(t, ts.URL+"/mcp/prod-ro", restrictedTok, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"get_system_info","arguments":{}}}`)
	if status != http.StatusOK || !strings.Contains(body, `"isError":true`) || !strings.Contains(body, "rate limit exceeded") {
		t.Fatalf("expected second burst call to be rate limited, status=%d body=%s", status, body)
	}
	if !strings.Contains(auditBuf.String(), `"reason":"rate limit exceeded`) {
		t.Fatalf("expected rate limit denial in audit log, got: %s", auditBuf.String())
	}
}

func issueMCPTestChannel(t *testing.T, scopes []string) (*channel.Store, channel.Detail) {
	t.Helper()
	store, err := channel.Open(filepath.Join(t.TempDir(), "channels.json"), "test-mcpserver-agent-key", "test-mcpserver-mcp-key", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	detail, err := store.Issue("ops", channel.Policy{
		Target: "prod-*", Mode: proto.ModeFull, AgentTTL: time.Hour, MCPScopes: scopes, MCPTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, detail
}

func addTestTarget(t *testing.T, reg *registry.Registry, channelID string, info proto.AgentInfo) {
	t.Helper()
	entry, ok := reg.Reserve(channelID, info, &fakeCaller{}, time.Now().Add(time.Hour))
	if !ok {
		t.Fatal("could not reserve test target")
	}
	reg.Activate(channelID, info.TargetID, entry.Generation)
}
