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
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"github.com/revmcp/revmcp/hub/internal/auth"
	"github.com/revmcp/revmcp/hub/internal/registry"
	"github.com/revmcp/revmcp/proto"
)

const (
	wsReadLimitBytes = 4 * 1024 * 1024
	registerTimeout  = 10 * time.Second
)

// Server accepts outbound WebSocket connections from agents and bridges them into yamux sessions.
type Server struct {
	signer      *auth.EnrollmentSigner
	registry    *registry.Registry
	hubVersion  string
	maxInflight int
	logger      *slog.Logger
}

// NewServer constructs a southbound tunnel server.
func NewServer(signer *auth.EnrollmentSigner, reg *registry.Registry, hubVersion string, maxInflight int, logger *slog.Logger) *Server {
	if maxInflight <= 0 {
		maxInflight = 16
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Server{
		signer:      signer,
		registry:    reg,
		hubVersion:  hubVersion,
		maxInflight: maxInflight,
		logger:      logger,
	}
}

// ServeHTTP upgrades an authenticated agent WebSocket connection, performs registration,
// and keeps the tunnel registered until the session closes.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := extractBearer(r.Header.Get("Authorization"))
	claims, err := s.signer.Verify(token)
	if err != nil {
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

	agentInfo, err := s.handleRegister(session, claims)
	if err != nil {
		s.logger.Warn("agent registration failed", "target_id", claims.TargetID, "err", err)
		_ = session.Close()
		connCancel()
		_ = wsConn.Close(websocket.StatusPolicyViolation, "registration rejected")
		return
	}

	caller := newSessionCaller(session, connCancel, wsConn, s.maxInflight)
	entry, replaced := s.registry.Register(agentInfo, caller)
	if replaced != nil {
		s.logger.Warn("replacing existing agent connection",
			"target_id", agentInfo.TargetID,
			"old_instance", replaced.Info.InstanceID,
			"new_instance", agentInfo.InstanceID,
		)
		_ = replaced.Caller.Close()
	}

	s.logger.Info("agent online",
		"target_id", agentInfo.TargetID,
		"mode", agentInfo.Mode,
		"arch", agentInfo.Arch,
		"in_container", agentInfo.InContainer,
	)

	<-session.CloseChan()
	s.registry.Unregister(agentInfo.TargetID, entry.Generation)
	_ = caller.Close()
	s.logger.Info("agent offline", "target_id", agentInfo.TargetID)
}

func (s *Server) handleRegister(session *yamux.Session, claims *auth.EnrollmentClaims) (proto.AgentInfo, error) {
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
			return proto.AgentInfo{}, fmt.Errorf("accept register stream: %w", res.err)
		}
		stream = res.stream
	case <-time.After(registerTimeout):
		return proto.AgentInfo{}, errors.New("register handshake timeout")
	}
	defer func() { _ = stream.Close() }()

	_ = stream.SetDeadline(time.Now().Add(registerTimeout))

	var req proto.Request
	if err := proto.ReadFrame(stream, &req); err != nil {
		return proto.AgentInfo{}, fmt.Errorf("read register request: %w", err)
	}
	if req.Method != proto.MethodAgentRegister {
		_ = proto.WriteFrame(stream, proto.Response{
			ID:    req.ID,
			Error: &proto.RPCError{Code: proto.ErrCodeInvalidArgument, Message: "expected agent.register"},
		})
		return proto.AgentInfo{}, fmt.Errorf("unexpected initial method %q", req.Method)
	}

	var regReq proto.RegisterRequest
	if err := json.Unmarshal(req.Params, &regReq); err != nil {
		return proto.AgentInfo{}, fmt.Errorf("unmarshal register params: %w", err)
	}
	if regReq.ProtoVersion != proto.ProtocolVersion {
		_ = proto.WriteFrame(stream, proto.Response{
			ID:    req.ID,
			Error: &proto.RPCError{Code: proto.ErrCodeUnsupported, Message: "unsupported protocol version"},
		})
		return proto.AgentInfo{}, fmt.Errorf("unsupported proto_version %d", regReq.ProtoVersion)
	}

	agentMode, err := proto.ParseMode(string(regReq.Agent.Mode))
	if err != nil || !claims.MaxMode.Allows(agentMode) {
		_ = proto.WriteFrame(stream, proto.Response{
			ID:    req.ID,
			Error: &proto.RPCError{Code: proto.ErrCodeModeDenied, Message: "agent mode exceeds enrollment token max_mode"},
		})
		return proto.AgentInfo{}, fmt.Errorf("agent mode %q exceeds token max_mode %q", regReq.Agent.Mode, claims.MaxMode)
	}

	// Authoritatively bind target_id from the signed enrollment token.
	info := regReq.Agent
	info.TargetID = claims.TargetID
	info.Mode = agentMode

	resultRaw, err := json.Marshal(proto.RegisterResponse{
		Accepted:   true,
		HubVersion: s.hubVersion,
	})
	if err != nil {
		return proto.AgentInfo{}, err
	}
	if err := proto.WriteFrame(stream, proto.Response{
		ID:     req.ID,
		Result: resultRaw,
	}); err != nil {
		return proto.AgentInfo{}, fmt.Errorf("write register response: %w", err)
	}
	return info, nil
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
		ID:     newRequestID(),
		Method: method,
		Params: rawParams,
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
