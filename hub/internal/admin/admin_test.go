package admin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	hubauth "github.com/revmcp/revmcp/hub/internal/auth"
	"github.com/revmcp/revmcp/hub/internal/config"
	"github.com/revmcp/revmcp/hub/internal/policy"
	"github.com/revmcp/revmcp/hub/internal/registry"
	"github.com/revmcp/revmcp/proto"
)

type mockShutdownCaller struct {
	lastReq proto.ShutdownRequest
}

func (m *mockShutdownCaller) Call(_ context.Context, method string, params any, dst any) error {
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

func TestAdminEndpointsAuthShutdownAndRevoke(t *testing.T) {
	t.Parallel()

	adminTok := "admin-secret-token"
	readTok := "readonly-secret-token"
	adminSum := sha256.Sum256([]byte(adminTok))
	readSum := sha256.Sum256([]byte(readTok))

	verifier, err := hubauth.NewStaticBearerVerifier([]config.ClientConfig{
		{
			Name:           "sre-admin",
			TokenSHA256:    hex.EncodeToString(adminSum[:]),
			Scopes:         []string{policy.ScopeRead, policy.ScopeAdmin},
			AllowedTargets: []string{"prod-*"},
		},
		{
			Name:           "ops-reader",
			TokenSHA256:    hex.EncodeToString(readSum[:]),
			Scopes:         []string{policy.ScopeRead},
			AllowedTargets: []string{"*"},
		},
	})
	if err != nil {
		t.Fatalf("NewStaticBearerVerifier: %v", err)
	}

	signer, err := hubauth.NewEnrollmentSigner("admin-test-signing-secret-123456")
	if err != nil {
		t.Fatalf("NewEnrollmentSigner: %v", err)
	}

	reg := registry.New()
	caller := &mockShutdownCaller{}
	reg.Register(proto.AgentInfo{TargetID: "prod-01", Hostname: "prod-01", Mode: proto.ModeReadOnly}, caller)
	reg.Register(proto.AgentInfo{TargetID: "dev-01", Hostname: "dev-01", Mode: proto.ModeFull}, &mockShutdownCaller{})

	var auditBuf bytes.Buffer
	h := NewHandler(reg, signer, policy.NewAuditLoggerWithWriter(&auditBuf))

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, verifier)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// 1. Non-admin caller must receive 403 Forbidden.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/targets", nil)
	req.Header.Set("Authorization", "Bearer "+readTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/targets as reader: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin scope, got %d", resp.StatusCode)
	}

	// 2. Admin lists targets filtered by allowed_targets (prod-* only).
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/admin/targets", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/targets as admin: %v", err)
	}
	var listBody bytes.Buffer
	_, _ = listBody.ReadFrom(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(listBody.String(), "prod-01") || strings.Contains(listBody.String(), "dev-01") {
		t.Fatalf("unexpected admin targets list: status=%d body=%s", resp.StatusCode, listBody.String())
	}

	// 3. Admin triggers remote self-destruct shutdown on prod-01.
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/admin/targets/prod-01/shutdown", strings.NewReader(`{"reason":"maintenance","self_destruct":true}`))
	req.Header.Set("Authorization", "Bearer "+adminTok)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST shutdown: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !caller.lastReq.SelfDestruct || caller.lastReq.Reason != "maintenance" {
		t.Fatalf("unexpected shutdown result: status=%d req=%+v", resp.StatusCode, caller.lastReq)
	}
	if !strings.Contains(auditBuf.String(), `"tool":"admin.shutdown"`) {
		t.Fatalf("expected admin.shutdown audit entry, got: %s", auditBuf.String())
	}

	// 4. Admin revokes an enrollment token JTI.
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/admin/tokens/revoke", strings.NewReader(`{"jti":"deadbeef12345678"}`))
	req.Header.Set("Authorization", "Bearer "+adminTok)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST revoke: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !signer.IsRevoked("deadbeef12345678") {
		t.Fatalf("expected jti to be revoked, status=%d", resp.StatusCode)
	}
}
