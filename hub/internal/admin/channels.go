package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/revmcp/revmcp/hub/internal/channel"
	"github.com/revmcp/revmcp/hub/internal/config"
	"github.com/revmcp/revmcp/hub/internal/policy"
	"github.com/revmcp/revmcp/hub/internal/registry"
)

type IssueChannel struct {
	Name    string             `json:"name"`
	Profile string             `json:"profile,omitempty"`
	Policy  config.IssuePolicy `json:"policy"`
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux, verifier sdkauth.TokenVerifier, policies config.ChannelsConfig) {
	adminAuth := sdkauth.RequireBearerToken(verifier, &sdkauth.RequireBearerTokenOptions{
		AllowMissingExpiration: true,
		Scopes:                 []string{policy.ScopeAdmin},
	})
	add := func(pattern string, handler http.HandlerFunc) {
		mux.Handle(pattern, adminAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			handler(w, r)
		})))
	}

	add("POST /admin/channels", func(w http.ResponseWriter, r *http.Request) {
		var issue IssueChannel
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&issue); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid issuance request")
			return
		}
		resolved, err := policies.Resolve(issue.Profile, issue.Policy)
		var detail channel.Detail
		if err == nil {
			detail, err = h.channels.Issue(issue.Name, resolved)
		}
		h.channelResponse(w, r, "issue", issue.Name, detail.ChannelID, "", http.StatusCreated, detail, err)
	})
	add("GET /admin/channels", func(w http.ResponseWriter, r *http.Request) {
		h.listChannels(w, r, "", false)
	})
	add("GET /admin/channels/{channel}", func(w http.ResponseWriter, r *http.Request) {
		h.listChannels(w, r, r.PathValue("channel"), false)
	})
	add("POST /admin/channels/{channel}/reveal", func(w http.ResponseWriter, r *http.Request) {
		h.listChannels(w, r, r.PathValue("channel"), true)
	})
	add("POST /admin/channels/{channel}/{operation}/{kind}", h.changeCredential)
	add("DELETE /admin/channels/{channel}", h.deleteChannel)
	add("POST /admin/channels/{channel}/targets/{target_id}/shutdown", h.kickChannelTarget)
	add("POST /admin/targets/expired/shutdown", h.kickExpiredTargets)
}

func (h *Handler) listChannels(w http.ResponseWriter, r *http.Request, name string, reveal bool) {
	details, err := h.channels.List(name, reveal, func(id string) []string {
		entries := h.registry.ListIn(id, "", "")
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Info.TargetID)
		}
		return names
	})
	if reveal {
		var detail channel.Detail
		if err == nil {
			detail = details[0]
		}
		h.channelResponse(w, r, "reveal", name, detail.ChannelID, "", http.StatusOK, detail, err)
		return
	}
	if name != "" {
		var detail channel.Detail
		if err == nil {
			detail = details[0]
		}
		h.channelResponse(w, r, "get", name, detail.ChannelID, "", http.StatusOK, detail, err)
		return
	}
	if err != nil {
		writeChannelError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, details)
}

func (h *Handler) changeCredential(w http.ResponseWriter, r *http.Request) {
	name, kind, operation := r.PathValue("channel"), r.PathValue("kind"), r.PathValue("operation")
	if operation != "rotate" && operation != "revoke" {
		writeJSONError(w, http.StatusNotFound, "unknown channel operation")
		return
	}
	detail, err := h.channels.Change(name, kind, operation == "rotate")
	h.channelResponse(w, r, operation, name, detail.ChannelID, kind, http.StatusOK, detail, err)
}

func (h *Handler) deleteChannel(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("channel")
	var callers []registry.Caller
	id, err := h.channels.Delete(name, func(id string) {
		callers = h.registry.Detach(id)
	})
	for _, caller := range callers {
		_ = caller.Close()
	}
	h.channelResponse(w, r, "delete", name, id, "", http.StatusOK, map[string]string{"deleted": name}, err)
}

func (h *Handler) kickChannelTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := h.channels.ID(r.PathValue("channel"))
	if !ok {
		writeChannelError(w, channel.ErrNotFound)
		return
	}
	h.shutdownTarget(w, r, id)
}

func (h *Handler) channelResponse(w http.ResponseWriter, r *http.Request, operation, name, channelID, kind string, status int, value any, err error) {
	info := sdkauth.TokenInfoFromContext(r.Context())
	args := map[string]any{"channel": name, "kind": kind}
	if err != nil {
		h.auditEvent(newTraceID(), info, channelID, "", "admin.channel."+operation, args, "deny", "channel operation rejected", time.Duration(0))
		writeChannelError(w, err)
		return
	}
	h.auditEvent(newTraceID(), info, channelID, "", "admin.channel."+operation, args, "allow", "completed", time.Duration(0))
	writeJSON(w, status, value)
}

func writeChannelError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, channel.ErrExists):
		writeJSONError(w, http.StatusConflict, err.Error())
	case errors.Is(err, channel.ErrInvalid):
		writeJSONError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, channel.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, err.Error())
	default:
		writeJSONError(w, http.StatusInternalServerError, "channel state operation failed")
	}
}
