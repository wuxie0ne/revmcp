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
	"sync"
	"testing"
	"time"

	"github.com/revmcp/revmcp/hub/internal/admin"
	hubauth "github.com/revmcp/revmcp/hub/internal/auth"
	"github.com/revmcp/revmcp/hub/internal/config"
	"github.com/revmcp/revmcp/hub/internal/mcpserver"
	"github.com/revmcp/revmcp/hub/internal/policy"
	"github.com/revmcp/revmcp/hub/internal/registry"
	"github.com/revmcp/revmcp/hub/internal/tunnel"
	"github.com/revmcp/revmcp/proto"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func copyBinary(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("open agent binary %q: %v", src, err)
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatalf("create copied binary %q: %v", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		t.Fatalf("copy binary: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close copied binary: %v", err)
	}
}

func mcpCall(t *testing.T, ctx context.Context, url, token string, payload any) (int, string) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err().Error()
		}
		t.Fatalf("HTTP Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var b bytes.Buffer
	_, _ = b.ReadFrom(resp.Body)
	return resp.StatusCode, b.String()
}

func TestRealAgentBinaryFullLifecycleAndSelfDestruct(t *testing.T) {
	agentBin := os.Getenv("REVMCP_AGENT_BIN")
	if agentBin == "" {
		candidate := filepath.Clean("../../../bin/revmcp-agent-linux-amd64")
		if _, err := os.Stat(candidate); err == nil {
			agentBin = candidate
		}
	}
	if agentBin == "" {
		t.Skip("REVMCP_AGENT_BIN not set and bin/revmcp-agent-linux-amd64 not built; run `make test-e2e`")
	}

	const adminTok = "e2e-admin-bearer-secret"
	sum := sha256.Sum256([]byte(adminTok))
	verifier, err := hubauth.NewStaticBearerVerifier([]config.ClientConfig{
		{
			Name:           "e2e-sre",
			TokenSHA256:    hex.EncodeToString(sum[:]),
			Scopes:         []string{policy.ScopeRead, policy.ScopeExecRestricted, policy.ScopeExecFull, policy.ScopeExecSession, policy.ScopeAdmin},
			AllowedTargets: []string{"*"},
		},
	})
	if err != nil {
		t.Fatalf("NewStaticBearerVerifier: %v", err)
	}

	signer, err := hubauth.NewEnrollmentSigner("e2e-signing-secret-key-1234567890")
	if err != nil {
		t.Fatalf("NewEnrollmentSigner: %v", err)
	}

	reg := registry.New()
	var auditBuf syncBuffer
	audit := policy.NewAuditLoggerWithWriter(&auditBuf)

	// Separate southbound tunnel listener (custom high port) and northbound MCP/Admin listener.
	tunnelSrv := tunnel.NewServer(signer, reg, audit, "e2e", 8, nil)
	tunnelTS := httptest.NewServer(tunnelSrv)
	defer tunnelTS.Close()

	mcpMux := http.NewServeMux()
	gw := mcpserver.NewGateway("e2e", reg, audit)
	gw.RegisterRoutes(mcpMux, verifier)
	admin.NewHandler(reg, signer, audit).RegisterRoutes(mcpMux, verifier)
	mcpTS := httptest.NewServer(mcpMux)
	defer mcpTS.Close()

	// Copy static agent binary so self-destruct removes only the temp copy.
	tmpDir := t.TempDir()
	agentCopy := filepath.Join(tmpDir, "revmcp-agent-copy")
	copyBinary(t, agentBin, agentCopy)

	enrollTok, _, err := signer.Issue("e2e-node-01", proto.ModeFull, time.Hour)
	if err != nil {
		t.Fatalf("Issue enrollment token: %v", err)
	}

	wsURL := "ws" + strings.TrimPrefix(tunnelTS.URL, "http") + "/agent/ws"
	agentCmd := exec.Command(agentCopy,
		"--hub", wsURL,
		"--token", enrollTok,
		"--mode", "full",
		"--tag", "env=e2e",
	)
	if err := agentCmd.Start(); err != nil {
		t.Fatalf("start agent binary: %v", err)
	}
	agentDone := make(chan error, 1)
	go func() { agentDone <- agentCmd.Wait() }()
	defer func() {
		if agentCmd.Process != nil {
			_ = agentCmd.Process.Kill()
		}
	}()

	// Wait for agent to come online in Hub registry.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := reg.Get("e2e-node-01"); ok {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if _, ok := reg.Get("e2e-node-01"); !ok {
		t.Fatal("real agent binary failed to register with Hub over ws:// custom port")
	}

	ctx := context.Background()

	// 1. MCP get_system_info via isolated /mcp/e2e-node-01.
	status, body := mcpCall(t, ctx, mcpTS.URL+"/mcp/e2e-node-01", adminTok, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "get_system_info", "arguments": map[string]any{}},
	})
	if status != http.StatusOK || !strings.Contains(body, "mounts") || !strings.Contains(body, "remote_output") {
		t.Fatalf("get_system_info failed: status=%d body=%s", status, body)
	}

	// 2. Default deny policy blocks /etc/shadow over real RPC.
	status, body = mcpCall(t, ctx, mcpTS.URL+"/mcp/e2e-node-01", adminTok, map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]any{"name": "read_file", "arguments": map[string]any{"path": "/etc/shadow"}},
	})
	if status != http.StatusOK || !strings.Contains(body, `"isError":true`) || !strings.Contains(body, "POLICY_DENIED") {
		t.Fatalf("expected POLICY_DENIED for /etc/shadow, status=%d body=%s", status, body)
	}

	// 3. Stateful shell_session end-to-end: open -> cd + export -> verify -> close.
	status, body = mcpCall(t, ctx, mcpTS.URL+"/mcp/e2e-node-01", adminTok, map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]any{"name": "shell_session", "arguments": map[string]any{"action": "open", "workdir": tmpDir}},
	})
	if status != http.StatusOK || !strings.Contains(body, "session_id") {
		t.Fatalf("shell_session open failed: status=%d body=%s", status, body)
	}

	// Extract session_id from text response.
	idx := strings.Index(body, `\"session_id\": \"`)
	if idx < 0 {
		t.Fatalf("could not locate session_id in response: %s", body)
	}
	rest := body[idx+len(`\"session_id\": \"`):]
	endIdx := strings.Index(rest, `\"`)
	sessionID := rest[:endIdx]

	_, _ = mcpCall(t, ctx, mcpTS.URL+"/mcp/e2e-node-01", adminTok, map[string]any{
		"jsonrpc": "2.0", "id": 4, "method": "tools/call",
		"params": map[string]any{"name": "shell_session", "arguments": map[string]any{"action": "run", "session_id": sessionID, "command": "export E2E_TOKEN_VAL=persisted123"}},
	})
	status, body = mcpCall(t, ctx, mcpTS.URL+"/mcp/e2e-node-01", adminTok, map[string]any{
		"jsonrpc": "2.0", "id": 5, "method": "tools/call",
		"params": map[string]any{"name": "shell_session", "arguments": map[string]any{"action": "run", "session_id": sessionID, "command": `echo "$E2E_TOKEN_VAL"`}},
	})
	if status != http.StatusOK || !strings.Contains(body, "persisted123") {
		t.Fatalf("shell_session did not persist env var: status=%d body=%s", status, body)
	}
	_, _ = mcpCall(t, ctx, mcpTS.URL+"/mcp/e2e-node-01", adminTok, map[string]any{
		"jsonrpc": "2.0", "id": 6, "method": "tools/call",
		"params": map[string]any{"name": "shell_session", "arguments": map[string]any{"action": "close", "session_id": sessionID}},
	})

	// 4. Trigger remote self-destruct via Admin API -> agent exits and removes its binary!
	req, _ := http.NewRequest(http.MethodPost, mcpTS.URL+"/admin/targets/e2e-node-01/shutdown", strings.NewReader(`{"reason":"e2e done","self_destruct":true}`))
	req.Header.Set("Authorization", "Bearer "+adminTok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("admin shutdown request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on admin shutdown, got %d", resp.StatusCode)
	}

	select {
	case err := <-agentDone:
		if err != nil {
			t.Fatalf("agent exited with error after shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not exit after remote shutdown")
	}

	if _, err := os.Stat(agentCopy); !os.IsNotExist(err) {
		t.Fatalf("expected self-destruct to remove %q, stat err=%v", agentCopy, err)
	}

	// 5. Verify --ttl auto-exit with a second binary copy.
	agentCopy2 := filepath.Join(tmpDir, "revmcp-agent-ttl")
	copyBinary(t, agentBin, agentCopy2)
	enrollTok2, _, _ := signer.Issue("e2e-ttl-node", proto.ModeReadOnly, time.Hour)
	ttlCmd := exec.Command(agentCopy2,
		"--hub", wsURL,
		"--token", enrollTok2,
		"--mode", "readonly",
		"--ttl", "300ms",
		"--self-destruct-on-exit",
	)
	start := time.Now()
	if err := ttlCmd.Run(); err != nil {
		t.Fatalf("ttl agent exited with error: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("ttl agent took too long to exit: %v", time.Since(start))
	}
	if _, err := os.Stat(agentCopy2); !os.IsNotExist(err) {
		t.Fatalf("expected --self-destruct-on-exit to remove %q, stat err=%v", agentCopy2, err)
	}
}
