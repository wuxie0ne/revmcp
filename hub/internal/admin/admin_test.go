package admin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	hubauth "github.com/revmcp/revmcp/hub/internal/auth"
	"github.com/revmcp/revmcp/hub/internal/channel"
	"github.com/revmcp/revmcp/hub/internal/config"
	"github.com/revmcp/revmcp/hub/internal/policy"
	"github.com/revmcp/revmcp/hub/internal/registry"
	"github.com/revmcp/revmcp/proto"
)

type mockShutdownCaller struct {
	lastReq proto.ShutdownRequest
	err     error
}

func (m *mockShutdownCaller) Call(_ context.Context, method string, params any, dst any) error {
	if m.err != nil {
		return m.err
	}
	if method == proto.MethodAgentShutdown {
		if req, ok := params.(proto.ShutdownRequest); ok {
			m.lastReq = req
		}
		raw, _ := json.Marshal(proto.ShutdownResult{Accepted: true})
		return json.Unmarshal(raw, dst)
	}
	return nil
}

func (m *mockShutdownCaller) Close() error { return nil }

func TestChannelAdminShutdown(t *testing.T) {
	t.Parallel()

	const token = "admin-secret-token"
	digest := sha256.Sum256([]byte(token))
	verifier, err := hubauth.NewAdminBearerVerifier(hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	store, err := channel.Open(filepath.Join(t.TempDir(), "channels.json"), "test-admin-agent-key", "test-admin-mcp-key", false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	policies := config.ChannelsConfig{}
	issuance, err := policies.Resolve("", config.IssuePolicy{Target: "prod-01"})
	if err != nil {
		t.Fatal(err)
	}
	detail, err := store.Issue("prod", issuance)
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.New()
	caller := &mockShutdownCaller{}
	entry, ok := reg.Reserve(detail.ChannelID, proto.AgentInfo{TargetID: "prod-01", Mode: proto.ModeReadOnly}, caller, detail.AgentExpires)
	if !ok {
		t.Fatal("could not reserve test target")
	}
	reg.Activate(detail.ChannelID, "prod-01", entry.Generation)

	var auditBuf bytes.Buffer
	mux := http.NewServeMux()
	NewHandler(reg, store, policy.NewAuditLoggerWithWriter(&auditBuf)).RegisterRoutes(mux, verifier, policies)

	for _, tc := range []struct {
		path   string
		bearer string
		status int
	}{
		{"/admin/channels/prod/targets/prod-01/shutdown", detail.Bearer, http.StatusUnauthorized},
		{"/admin/targets/prod-01/shutdown", token, http.StatusNotFound},
		{"/admin/tokens/revoke", token, http.StatusNotFound},
		{"/admin/channels/prod/targets/prod-01/shutdown", token, http.StatusOK},
	} {
		req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(`{"reason":"maintenance","self_destruct":true}`))
		req.Header.Set("Authorization", "Bearer "+tc.bearer)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, req)
		if response.Code != tc.status {
			t.Fatalf("%s: got %d, want %d", tc.path, response.Code, tc.status)
		}
	}
	if !caller.lastReq.SelfDestruct || caller.lastReq.Reason != "maintenance" {
		t.Fatalf("unexpected shutdown request: %+v", caller.lastReq)
	}
	if !strings.Contains(auditBuf.String(), `"tool":"admin.shutdown"`) {
		t.Fatalf("expected admin.shutdown audit entry, got: %s", auditBuf.String())
	}

	for _, tc := range []struct {
		targetID string
		pending  bool
		err      error
	}{
		{targetID: "expired-ok"},
		{targetID: "expired-failed", err: errors.New("Agent unreachable")},
		{targetID: "pending", pending: true},
	} {
		entry, ok := reg.Reserve(detail.ChannelID, proto.AgentInfo{TargetID: tc.targetID},
			&mockShutdownCaller{err: tc.err}, time.Now().Add(-time.Second))
		if !ok {
			t.Fatal("could not reserve expired target")
		}
		if !tc.pending {
			reg.Activate(detail.ChannelID, tc.targetID, entry.Generation)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/targets/expired/shutdown", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, req)
	var batch ExpiredShutdownResult
	if err := json.Unmarshal(response.Body.Bytes(), &batch); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || batch.Failed != 1 || len(batch.Targets) != 2 ||
		batch.Targets[0].TargetID != "expired-failed" || batch.Targets[0].Accepted || batch.Targets[0].Error != "Agent unreachable" ||
		batch.Targets[1].TargetID != "expired-ok" || !batch.Targets[1].Accepted {
		t.Fatalf("unexpected bulk response: status=%d result=%+v", response.Code, batch)
	}
}
