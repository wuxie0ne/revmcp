package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/revmcp/revmcp/hub/internal/channel"
	"github.com/revmcp/revmcp/hub/internal/policy"
	"github.com/revmcp/revmcp/hub/internal/registry"
	"github.com/revmcp/revmcp/proto"
)

// ShutdownPayload is the JSON request body for channel target shutdown.
type ShutdownPayload struct {
	Reason       string `json:"reason,omitempty"`
	SelfDestruct bool   `json:"self_destruct,omitempty"`
}

type ExpiredShutdownResult struct {
	Targets []ExpiredShutdownTarget `json:"targets"`
	Failed  int                     `json:"failed"`
}

type ExpiredShutdownTarget struct {
	ChannelID string `json:"channel_id"`
	TargetID  string `json:"target_id"`
	Accepted  bool   `json:"accepted"`
	Error     string `json:"error,omitempty"`
}

// Handler serves authenticated Hub Admin HTTP endpoints (never exposed as MCP tools to LLMs).
type Handler struct {
	registry *registry.Registry
	audit    *policy.AuditLogger
	channels *channel.Store
}

// NewHandler creates an Admin HTTP Handler.
func NewHandler(reg *registry.Registry, store *channel.Store, audit *policy.AuditLogger) *Handler {
	return &Handler{
		registry: reg,
		channels: store,
		audit:    audit,
	}
}

func (h *Handler) shutdownTarget(w http.ResponseWriter, r *http.Request, channelID string) {
	start := time.Now()
	traceID := newTraceID()
	info := sdkauth.TokenInfoFromContext(r.Context())
	targetID := strings.TrimSpace(r.PathValue("target_id"))

	payload, err := readShutdownPayload(w, r)
	if err != nil {
		h.auditEvent(traceID, info, channelID, targetID, "admin.shutdown", nil, "deny", "invalid json payload", time.Since(start))
		writeJSONError(w, http.StatusBadRequest, "invalid json payload")
		return
	}

	args := map[string]any{"reason": payload.Reason, "self_destruct": payload.SelfDestruct}
	if err := policy.Authorize(info, policy.ScopeAdmin, ""); err != nil {
		h.auditEvent(traceID, info, channelID, targetID, "admin.shutdown", args, "deny", err.Error(), time.Since(start))
		writeJSONError(w, http.StatusForbidden, err.Error())
		return
	}

	entry, ok := h.registry.GetIn(channelID, targetID)
	if !ok {
		msg := fmt.Sprintf("target %q is offline", targetID)
		h.auditEvent(traceID, info, channelID, targetID, "admin.shutdown", args, "deny", msg, time.Since(start))
		writeJSONError(w, http.StatusNotFound, msg)
		return
	}

	accepted, err := h.requestShutdown(r.Context(), traceID, info, entry, payload)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"accepted":      accepted,
		"target_id":     targetID,
		"self_destruct": payload.SelfDestruct,
	})
}

func (h *Handler) kickExpiredTargets(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	traceID := newTraceID()
	info := sdkauth.TokenInfoFromContext(r.Context())
	payload, err := readShutdownPayload(w, r)
	if err != nil || payload.SelfDestruct {
		const reason = "expected a shutdown payload without self_destruct"
		h.auditEvent(traceID, info, "", "", "admin.shutdown_expired", nil, "deny", reason, time.Since(start))
		writeJSONError(w, http.StatusBadRequest, reason)
		return
	}
	if err := policy.Authorize(info, policy.ScopeAdmin, ""); err != nil {
		h.auditEvent(traceID, info, "", "", "admin.shutdown_expired", nil, "deny", err.Error(), time.Since(start))
		writeJSONError(w, http.StatusForbidden, err.Error())
		return
	}
	if payload.Reason == "" {
		payload.Reason = "Agent enrollment credential expired"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	entries := h.registry.ExpiredEnrollments(time.Now())
	result := ExpiredShutdownResult{Targets: make([]ExpiredShutdownTarget, len(entries))}
	workers := min(8, len(entries))
	var group sync.WaitGroup
	for worker := range workers {
		group.Go(func() {
			for i := worker; i < len(entries); i += workers {
				entry := entries[i]
				callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				accepted, err := h.requestShutdown(callCtx, newTraceID(), info, entry, payload)
				cancel()
				target := ExpiredShutdownTarget{ChannelID: entry.ChannelID, TargetID: entry.Info.TargetID, Accepted: accepted}
				switch {
				case err != nil:
					target.Error = err.Error()
				case !accepted:
					target.Error = "Agent did not accept the shutdown request"
				}
				result.Targets[i] = target
			}
		})
	}
	group.Wait()
	for _, target := range result.Targets {
		if !target.Accepted {
			result.Failed++
		}
	}
	h.auditEvent(traceID, info, "", "", "admin.shutdown_expired",
		map[string]any{"matched": len(entries), "failed": result.Failed, "reason": payload.Reason},
		"allow", "", time.Since(start))
	writeJSON(w, http.StatusOK, result)
}

func readShutdownPayload(w http.ResponseWriter, r *http.Request) (ShutdownPayload, error) {
	var payload ShutdownPayload
	if r.Body == nil {
		return payload, nil
	}
	defer func() { _ = r.Body.Close() }()
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&payload)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return payload, err
}

func (h *Handler) requestShutdown(ctx context.Context, traceID string, info *sdkauth.TokenInfo, entry *registry.Entry, payload ShutdownPayload) (bool, error) {
	start := time.Now()
	var res proto.ShutdownResult
	err := ctx.Err()
	if err == nil {
		err = entry.Caller.Call(policy.WithTraceID(ctx, traceID), proto.MethodAgentShutdown, proto.ShutdownRequest{
			Reason: payload.Reason, SelfDestruct: payload.SelfDestruct,
		}, &res)
	}
	decision, reason := "allow", ""
	switch {
	case err != nil:
		decision, reason = "deny", err.Error()
	case !res.Accepted:
		decision, reason = "deny", "Agent did not accept the shutdown request"
	}
	args := map[string]any{"reason": payload.Reason, "self_destruct": payload.SelfDestruct}
	h.auditEvent(traceID, info, entry.ChannelID, entry.Info.TargetID, "admin.shutdown", args, decision, reason, time.Since(start))
	return err == nil && res.Accepted, err
}

func (h *Handler) auditEvent(traceID string, info *sdkauth.TokenInfo, channelID, targetID, tool string, args map[string]any, decision, reason string, dur time.Duration) {
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
		ChannelID:    channelID,
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
