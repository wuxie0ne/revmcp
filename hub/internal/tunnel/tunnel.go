package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"github.com/revmcp/revmcp/hub/internal/channel"
	"github.com/revmcp/revmcp/hub/internal/policy"
	"github.com/revmcp/revmcp/hub/internal/registry"
	"github.com/revmcp/revmcp/proto"
)

const (
	wsReadLimitBytes     = 4 * 1024 * 1024
	registerTimeout      = 10 * time.Second
	registerReplyTimeout = 2 * time.Second
)

// Server accepts outbound WebSocket connections from agents and bridges them into yamux sessions.
type Server struct {
	channels    *channel.Store
	registry    *registry.Registry
	audit       *policy.AuditLogger
	hubVersion  string
	maxInflight int
	logger      *slog.Logger
}

// NewServer constructs a southbound tunnel server.
func NewServer(store *channel.Store, reg *registry.Registry, audit *policy.AuditLogger, hubVersion string, maxInflight int, logger *slog.Logger) *Server {
	if maxInflight <= 0 {
		maxInflight = 16
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Server{
		channels:    store,
		registry:    reg,
		audit:       audit,
		hubVersion:  hubVersion,
		maxInflight: maxInflight,
		logger:      logger,
	}
}

// ServeHTTP upgrades an authenticated agent WebSocket connection, performs registration,
// and keeps the tunnel registered until the session closes.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := extractBearer(r.Header.Get("Authorization"))
	if _, _, err := s.channels.Verify(token, channel.Agent); err != nil {
		http.Error(w, "unauthorized enrollment token", http.StatusUnauthorized)
		return
	}

	wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // Non-browser agent clients do not send Origin headers.
	})
	if err != nil {
		s.logger.Warn("websocket accept failed", "err", err)
		return
	}

	// Critical rule: raise ReadLimit from default 32KB to 4MB before wrapping in NetConn.
	wsConn.SetReadLimit(wsReadLimitBytes)

	// Critical rule: NEVER pass http.Request.Context() into websocket.NetConn.
	connCtx, connCancel := context.WithCancel(context.Background())
	netConn := websocket.NetConn(connCtx, wsConn, websocket.MessageBinary)

	yCfg := yamux.DefaultConfig()
	yCfg.EnableKeepAlive = true
	yCfg.KeepAliveInterval = 10 * time.Second
	yCfg.ConnectionWriteTimeout = 15 * time.Second
	yCfg.LogOutput = io.Discard

	session, err := yamux.Server(netConn, yCfg)
	if err != nil {
		connCancel()
		_ = wsConn.Close(websocket.StatusInternalError, "yamux init failed")
		return
	}

	caller := newSessionCaller(session, connCancel, wsConn, s.maxInflight)
	entry, channelID, err := s.handleRegister(session, caller, token)
	if err != nil {
		s.logger.Warn("agent registration failed", "err", err)
		_ = caller.Close()
		return
	}
	agentInfo := entry.Info

	s.logger.Info("agent online",
		"channel_id", channelID,
		"target_id", agentInfo.TargetID,
		"mode", agentInfo.Mode,
		"arch", agentInfo.Arch,
		"in_container", agentInfo.InContainer,
	)

	<-session.CloseChan()
	s.registry.UnregisterIn(channelID, agentInfo.TargetID, entry.Generation)
	_ = caller.Close()
	s.logger.Info("agent offline", "channel_id", channelID, "target_id", agentInfo.TargetID)
}

func (s *Server) handleRegister(session *yamux.Session, caller *sessionCaller, token string) (*registry.Entry, string, error) {
	type acceptResult struct {
		stream *yamux.Stream
		err    error
	}
	ch := make(chan acceptResult, 1)
	go func() {
		st, err := session.AcceptStream()
		ch <- acceptResult{stream: st, err: err}
	}()

	var stream *yamux.Stream
	select {
	case res := <-ch:
		if res.err != nil {
			return nil, "", fmt.Errorf("accept register stream: %w", res.err)
		}
		stream = res.stream
	case <-time.After(registerTimeout):
		return nil, "", errors.New("register handshake timeout")
	}
	defer func() { _ = stream.Close() }()

	deadline := time.Now().Add(registerTimeout)
	_ = stream.SetDeadline(deadline)

	var req proto.Request
	if err := proto.ReadFrame(stream, &req); err != nil {
		return nil, "", fmt.Errorf("read register request: %w", err)
	}
	if req.Method != proto.MethodAgentRegister {
		_ = proto.WriteFrame(stream, proto.Response{
			ID:    req.ID,
			Error: &proto.RPCError{Code: proto.ErrCodeInvalidArgument, Message: "expected agent.register"},
		})
		return nil, "", fmt.Errorf("unexpected initial method %q", req.Method)
	}

	var regReq proto.RegisterRequest
	if err := json.Unmarshal(req.Params, &regReq); err != nil {
		return nil, "", fmt.Errorf("unmarshal register params: %w", err)
	}
	if regReq.ProtoVersion != proto.ProtocolVersion {
		_ = proto.WriteFrame(stream, proto.Response{
			ID:    req.ID,
			Error: &proto.RPCError{Code: proto.ErrCodeUnsupported, Message: "unsupported protocol version"},
		})
		return nil, "", fmt.Errorf("unsupported proto_version %d", regReq.ProtoVersion)
	}

	reply := func() error {
		result, err := json.Marshal(proto.RegisterResponse{Accepted: true, HubVersion: s.hubVersion})
		if err != nil {
			return err
		}
		// yamux can block in its session send queue beyond a stream deadline.
		// Cancel the transport to bound the entire response write.
		remaining := min(registerReplyTimeout, time.Until(deadline))
		if remaining <= 0 {
			return errors.New("register response timeout")
		}
		timer := time.AfterFunc(remaining, func() {
			caller.connCancel()
			_ = caller.wsConn.CloseNow()
		})
		err = proto.WriteFrame(stream, proto.Response{ID: req.ID, Result: result})
		if !timer.Stop() {
			return errors.New("register response timeout")
		}
		return err
	}
	entry, channelID, err := s.register(token, regReq, caller, reply)
	var rpcErr *proto.RPCError
	if errors.As(err, &rpcErr) {
		_ = proto.WriteFrame(stream, proto.Response{ID: req.ID, Error: rpcErr})
	}
	return entry, channelID, err
}

func (s *Server) register(token string, req proto.RegisterRequest, caller *sessionCaller, reply func() error) (*registry.Entry, string, error) {
	start := time.Now()
	info := req.Agent
	var entry *registry.Entry
	channelID, err := s.channels.AdmitAgent(token, func(record channel.Record) error {
		matches, _ := path.Match(record.Policy.Target, info.TargetID)
		if !channel.ValidName(info.TargetID) || !matches {
			return &proto.RPCError{Code: proto.ErrCodeInvalidArgument, Message: "target ID matching the channel target rule is required"}
		}
		mode, err := proto.ParseMode(string(info.Mode))
		if err != nil || !record.Policy.Mode.Allows(mode) {
			return &proto.RPCError{Code: proto.ErrCodeModeDenied, Message: "invalid Agent mode or mode exceeds channel maximum"}
		}
		info.Mode = mode
		var reserved bool
		entry, reserved = s.registry.Reserve(record.ID, info, caller, time.Unix(record.Agent.Expires, 0))
		if !reserved {
			return &proto.RPCError{Code: proto.ErrCodeInvalidArgument, Message: "target already connected in channel"}
		}
		if err := reply(); err != nil {
			s.registry.UnregisterIn(record.ID, info.TargetID, entry.Generation)
			return err
		}
		s.registry.Activate(record.ID, info.TargetID, entry.Generation)
		return nil
	})
	reason, decision := "registered", "allow"
	if err != nil {
		reason, decision = "registration failed", "deny"
		var rpcErr *proto.RPCError
		if errors.As(err, &rpcErr) {
			reason = rpcErr.Message
		}
	}
	targetID := ""
	if channelID != "" && channel.ValidName(info.TargetID) {
		targetID = info.TargetID
	}
	s.auditRegistration(channelID, targetID, decision, reason, time.Since(start))
	return entry, channelID, err
}

func (s *Server) auditRegistration(channelID, targetID, decision, reason string, duration time.Duration) {
	if s.audit != nil {
		_ = s.audit.Log(policy.AuditEntry{
			TraceID: newRequestID(), User: "agent:" + targetID, ChannelID: channelID, TargetID: targetID,
			Tool: "agent.register", Decision: decision, Reason: reason, DurationMS: duration.Milliseconds(),
		})
	}
}

type sessionCaller struct {
	session    *yamux.Session
	connCancel context.CancelFunc
	wsConn     *websocket.Conn
	sem        chan struct{}
}

func newSessionCaller(session *yamux.Session, connCancel context.CancelFunc, wsConn *websocket.Conn, maxInflight int) *sessionCaller {
	return &sessionCaller{
		session:    session,
		connCancel: connCancel,
		wsConn:     wsConn,
		sem:        make(chan struct{}, maxInflight),
	}
}

// Call executes one RPC on a dedicated yamux stream and closes the stream immediately on ctx.Done().
func (c *sessionCaller) Call(ctx context.Context, method string, params any, resultDst any) error {
	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	case <-ctx.Done():
		return ctx.Err()
	}

	stream, err := c.session.OpenStream()
	if err != nil {
		return fmt.Errorf("tunnel: open stream: %w", err)
	}

	done := make(chan struct{})
	defer close(done)

	// Cascade cancellation: closing the stream signals EOF/RST to the agent immediately.
	go func() {
		select {
		case <-ctx.Done():
			_ = stream.Close()
		case <-done:
		}
	}()
	defer func() { _ = stream.Close() }()

	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("tunnel: marshal params: %w", err)
		}
		rawParams = b
	}

	req := proto.Request{
		ID:      newRequestID(),
		TraceID: policy.TraceIDFromContext(ctx),
		Method:  method,
		Params:  rawParams,
	}
	if err := proto.WriteFrame(stream, req); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("tunnel: write request: %w", err)
	}

	var resp proto.Response
	if err := proto.ReadFrame(stream, &resp); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("tunnel: read response: %w", err)
	}
	if resp.Error != nil {
		return resp.Error
	}
	if resultDst != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, resultDst); err != nil {
			return fmt.Errorf("tunnel: unmarshal result: %w", err)
		}
	}
	return nil
}

func (c *sessionCaller) Close() error {
	c.connCancel()
	err := c.session.Close()
	_ = c.wsConn.Close(websocket.StatusNormalClosure, "closed")
	return err
}

func extractBearer(header string) string {
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "bearer") {
		return ""
	}
	return fields[1]
}

func newRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
