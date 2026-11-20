package admin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	hubauth "github.com/revmcp/revmcp/hub/internal/auth"
	"github.com/revmcp/revmcp/hub/internal/policy"
	"github.com/revmcp/revmcp/hub/internal/registry"
	"github.com/revmcp/revmcp/proto"
)

// TargetDetail describes an online agent returned by GET /admin/targets.
type TargetDetail struct {
	TargetID      string            `json:"target_id"`
	InstanceID    string            `json:"instance_id,omitempty"`
	Hostname      string            `json:"hostname"`
	OS            string            `json:"os"`
	Kernel        string            `json:"kernel"`
	Arch          string            `json:"arch"`
	InContainer   bool              `json:"in_container"`
	Mode          proto.Mode        `json:"mode"`
	Version       string            `json:"version"`
	Tags          map[string]string `json:"tags,omitempty"`
	ConnectedAt   time.Time         `json:"connected_at"`
	OnlineSeconds int64             `json:"online_seconds"`
}

// ShutdownPayload is the JSON request body for POST /admin/targets/{target_id}/shutdown.
type ShutdownPayload struct {
	Reason       string `json:"reason,omitempty"`
	SelfDestruct bool   `json:"self_destruct,omitempty"`
}

// RevokePayload is the JSON request body for POST /admin/tokens/revoke.
type RevokePayload struct {
	JTI string `json:"jti"`
}

// Handler serves authenticated Hub Admin HTTP endpoints (never exposed as MCP tools to LLMs).
type Handler struct {
	registry *registry.Registry
	signer   *hubauth.EnrollmentSigner
	audit    *policy.AuditLogger
}

// NewHandler creates an Admin HTTP Handler.
func NewHandler(reg *registry.Registry, signer *hubauth.EnrollmentSigner, audit *policy.AuditLogger) *Handler {
	return &Handler{
		registry: reg,
		signer:   signer,
		audit:    audit,
	}
}

// RegisterRoutes mounts /admin/* endpoints behind Bearer auth requiring the "admin" scope.
func (h *Handler) RegisterRoutes(mux *http.ServeMux, verifier sdkauth.TokenVerifier) {
	authMW := sdkauth.RequireBearerToken(verifier, &sdkauth.RequireBearerTokenOptions{
		AllowMissingExpiration: true,
		Scopes:                 []string{policy.ScopeAdmin},
	})

	mux.Handle("GET /admin/targets", authMW(http.HandlerFunc(h.handleListTargets)))
	mux.Handle("POST /admin/targets/{target_id}/shutdown", authMW(http.HandlerFunc(h.handleShutdownTarget)))
	mux.Handle("POST /admin/tokens/revoke", authMW(http.HandlerFunc(h.handleRevokeToken)))
	mux.Handle("GET /admin/tokens/revoked", authMW(http.HandlerFunc(h.handleListRevoked)))
}

func (h *Handler) handleListTargets(w http.ResponseWriter, r *http.Request) {
	info := sdkauth.TokenInfoFromContext(r.Context())
	if err := policy.Authorize(info, policy.ScopeAdmin, ""); err != nil {
		writeJSONError(w, http.StatusForbidden, err.Error())
		return
	}

	tagKey, tagVal, _ := strings.Cut(strings.TrimSpace(r.URL.Query().Get("tag")), "=")
	allowed := hubauth.AllowedTargetsFromToken(info)
	entries := h.registry.List(tagKey, tagVal)

	targets := make([]TargetDetail, 0, len(entries))
	for _, e := range entries {
		if !policy.TargetAllowed(allowed, e.Info.TargetID) {
			continue
		}
		targets = append(targets, TargetDetail{
			TargetID:      e.Info.TargetID,
			InstanceID:    e.Info.InstanceID,
			Hostname:      e.Info.Hostname,
			OS:            e.Info.OS,
			Kernel:        e.Info.Kernel,
			Arch:          e.Info.Arch,
			InContainer:   e.Info.InContainer,
			Mode:          e.Info.Mode,
			Version:       e.Info.Version,
			Tags:          e.Info.Tags,
			ConnectedAt:   e.ConnectedAt,
			OnlineSeconds: int64(time.Since(e.ConnectedAt).Seconds()),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"targets": targets})
}

func (h *Handler) handleShutdownTarget(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	traceID := newTraceID()
	info := sdkauth.TokenInfoFromContext(r.Context())
	targetID := strings.TrimSpace(r.PathValue("target_id"))

	var payload ShutdownPayload
	if r.Body != nil {
		defer func() { _ = r.Body.Close() }()
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&payload); err != nil && err.Error() != "EOF" {
			writeJSONError(w, http.StatusBadRequest, "invalid json payload")
			return
		}
	}

	args := map[string]any{"reason": payload.Reason, "self_destruct": payload.SelfDestruct}
	if err := policy.Authorize(info, policy.ScopeAdmin, targetID); err != nil {
		h.auditEvent(traceID, info, targetID, "admin.shutdown", args, "deny", err.Error(), time.Since(start))
		writeJSONError(w, http.StatusForbidden, err.Error())
		return
	}

	entry, ok := h.registry.Get(targetID)
	if !ok {
		msg := fmt.Sprintf("target %q is offline", targetID)
		h.auditEvent(traceID, info, targetID, "admin.shutdown", args, "deny", msg, time.Since(start))
		writeJSONError(w, http.StatusNotFound, msg)
		return
	}

	var res proto.ShutdownResult
	callCtx := policy.WithTraceID(r.Context(), traceID)
	if err := entry.Caller.Call(callCtx, proto.MethodAgentShutdown, proto.ShutdownRequest{
		Reason:       payload.Reason,
		SelfDestruct: payload.SelfDestruct,
	}, &res); err != nil {
		h.auditEvent(traceID, info, targetID, "admin.shutdown", args, "deny", err.Error(), time.Since(start))
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}

	h.auditEvent(traceID, info, targetID, "admin.shutdown", args, "allow", "", time.Since(start))
	writeJSON(w, http.StatusOK, map[string]any{
		"accepted":      res.Accepted,
		"target_id":     targetID,
		"self_destruct": payload.SelfDestruct,
	})
}

func (h *Handler) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	traceID := newTraceID()
	info := sdkauth.TokenInfoFromContext(r.Context())

	if err := policy.Authorize(info, policy.ScopeAdmin, ""); err != nil {
		h.auditEvent(traceID, info, "", "admin.token.revoke", nil, "deny", err.Error(), time.Since(start))
		writeJSONError(w, http.StatusForbidden, err.Error())
		return
	}

	var payload RevokePayload
	if r.Body == nil {
		writeJSONError(w, http.StatusBadRequest, "missing request body")
		return
	}
	defer func() { _ = r.Body.Close() }()
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json payload")
		return
	}
	jti := strings.TrimSpace(payload.JTI)
	if jti == "" {
		writeJSONError(w, http.StatusBadRequest, "jti is required")
		return
	}

	h.signer.Revoke(jti)
	h.auditEvent(traceID, info, "", "admin.token.revoke", map[string]any{"jti": jti}, "allow", "", time.Since(start))
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true, "jti": jti})
}

func (h *Handler) handleListRevoked(w http.ResponseWriter, r *http.Request) {
	info := sdkauth.TokenInfoFromContext(r.Context())
	if err := policy.Authorize(info, policy.ScopeAdmin, ""); err != nil {
		writeJSONError(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked_jtis": h.signer.RevokedJTIs()})
}

func (h *Handler) auditEvent(traceID string, info *sdkauth.TokenInfo, targetID, tool string, args map[string]any, decision, reason string, dur time.Duration) {
	if h.audit == nil {
		return
	}
	user := "anonymous"
	if info != nil && info.UserID != "" {
		user = info.UserID
	}
	_ = h.audit.Log(policy.AuditEntry{
		TraceID:      traceID,
		User:         user,
		TargetID:     targetID,
		Tool:         tool,
		ArgsRedacted: args,
		Decision:     decision,
		Reason:       reason,
		DurationMS:   dur.Milliseconds(),
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func newTraceID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("adm-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
