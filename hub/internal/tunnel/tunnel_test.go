package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"github.com/revmcp/revmcp/hub/internal/auth"
	"github.com/revmcp/revmcp/hub/internal/policy"
	"github.com/revmcp/revmcp/hub/internal/registry"
	"github.com/revmcp/revmcp/proto"
)

func dialTestAgent(t *testing.T, wsURL, token string, info proto.AgentInfo, handler func(context.Context, proto.Request) (any, *proto.RPCError)) (*yamux.Session, func()) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wsConn, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}},
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	wsConn.SetReadLimit(wsReadLimitBytes)

	connCtx, connCancel := context.WithCancel(context.Background())
	netConn := websocket.NetConn(connCtx, wsConn, websocket.MessageBinary)
	yCfg := yamux.DefaultConfig()
	yCfg.LogOutput = io.Discard
	sess, err := yamux.Client(netConn, yCfg)
	if err != nil {
		connCancel()
		t.Fatalf("yamux.Client failed: %v", err)
	}

	// Perform agent.register handshake.
	st, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream register failed: %v", err)
	}
	rawParams, _ := json.Marshal(proto.RegisterRequest{
		ProtoVersion: proto.ProtocolVersion,
		Agent:        info,
	})
	if err := proto.WriteFrame(st, proto.Request{ID: "reg", Method: proto.MethodAgentRegister, Params: rawParams}); err != nil {
		t.Fatalf("WriteFrame register failed: %v", err)
	}
	var regResp proto.Response
	if err := proto.ReadFrame(st, &regResp); err != nil {
		t.Fatalf("ReadFrame register failed: %v", err)
	}
	_ = st.Close()
	if regResp.Error != nil {
		_ = sess.Close()
		connCancel()
		t.Fatalf("register rejected: %v", regResp.Error)
	}

	go func() {
		for {
			s, err := sess.AcceptStream()
			if err != nil {
				return
			}
			go func(stream *yamux.Stream) {
				defer func() { _ = stream.Close() }()
				var req proto.Request
				if err := proto.ReadFrame(stream, &req); err != nil {
					return
				}
				rpcCtx, rpcCancel := context.WithCancel(context.Background())
				defer rpcCancel()
				go func() {
					var b [1]byte
					if _, err := stream.Read(b[:]); err != nil {
						rpcCancel()
					}
				}()
				res, rpcErr := handler(rpcCtx, req)
				resp := proto.Response{ID: req.ID, Error: rpcErr}
				if rpcErr == nil && res != nil {
					resp.Result, _ = json.Marshal(res)
				}
				_ = proto.WriteFrame(stream, resp)
			}(s)
		}
	}()

	return sess, func() {
		_ = sess.Close()
		connCancel()
		_ = wsConn.Close(websocket.StatusNormalClosure, "bye")
	}
}

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

func TestHubTunnelRoundTripTraceAndCancel(t *testing.T) {
	t.Parallel()

	signer, err := auth.NewEnrollmentSigner("hub-tunnel-test-secret-key-12345")
	if err != nil {
		t.Fatalf("NewEnrollmentSigner: %v", err)
	}
	reg := registry.New()
	var auditBuf syncBuffer
	audit := policy.NewAuditLoggerWithWriter(&auditBuf)
	srv := NewServer(signer, reg, audit, "test", 8, nil)

	ts := httptest.NewServer(srv)
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")

	// 1. Unauthorized dial must return 401.
	_, resp, err := websocket.Dial(context.Background(), wsURL, nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err == nil || (resp != nil && resp.StatusCode != http.StatusUnauthorized) {
		t.Fatalf("expected 401 unauthorized on missing token, err=%v resp=%v", err, resp)
	}

	// 2. Valid token registration + TraceID propagation + cascade cancel.
	tok, _, err := signer.Issue("prod-01", proto.ModeRestricted, time.Hour)
	if err != nil {
		t.Fatalf("Issue token: %v", err)
	}

	gotTraceCh := make(chan string, 1)
	canceledCh := make(chan struct{}, 1)

	_, cleanup := dialTestAgent(t, wsURL, tok, proto.AgentInfo{
		TargetID:   "prod-01",
		InstanceID: "inst-1",
		Mode:       proto.ModeRestricted,
	}, func(ctx context.Context, req proto.Request) (any, *proto.RPCError) {
		if req.Method == proto.MethodSysInfo {
			gotTraceCh <- req.TraceID
			return &proto.SysInfoResult{Hostname: "prod-01", CPUCores: 2}, nil
		}
		if req.Method == "test.slow" {
			<-ctx.Done()
			canceledCh <- struct{}{}
			return nil, &proto.RPCError{Code: proto.ErrCodeCancelled, Message: "cancelled"}
		}
		return nil, nil
	})
	defer cleanup()

	// Wait until registry sees prod-01 online.
	var entry *registry.Entry
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if e, ok := reg.Get("prod-01"); ok {
			entry = e
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if entry == nil {
		t.Fatal("prod-01 did not register in time")
	}

	var sysRes proto.SysInfoResult
	callCtx := policy.WithTraceID(context.Background(), "trace-xyz-999")
	if err := entry.Caller.Call(callCtx, proto.MethodSysInfo, nil, &sysRes); err != nil {
		t.Fatalf("Call(sys.info) failed: %v", err)
	}
	if sysRes.Hostname != "prod-01" {
		t.Fatalf("unexpected hostname: %+v", sysRes)
	}
	if trace := <-gotTraceCh; trace != "trace-xyz-999" {
		t.Fatalf("expected TraceID trace-xyz-999, got %q", trace)
	}

	// Test cascade cancellation from Hub context.
	cancelCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := entry.Caller.Call(cancelCtx, "test.slow", nil, nil); err == nil {
		t.Fatal("expected error from cancelled Call")
	}
	select {
	case <-canceledCh:
	case <-time.After(2 * time.Second):
		t.Fatal("expected remote agent handler to cancel promptly")
	}

	// 3. Different instance_id taking over active target must emit high-severity audit warning.
	_, cleanup2 := dialTestAgent(t, wsURL, tok, proto.AgentInfo{
		TargetID:   "prod-01",
		InstanceID: "inst-2-intruder",
		Mode:       proto.ModeRestricted,
	}, func(_ context.Context, _ proto.Request) (any, *proto.RPCError) {
		return &proto.PingResult{}, nil
	})
	defer cleanup2()

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(auditBuf.String(), "agent.register.takeover") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(auditBuf.String(), "agent.register.takeover") || !strings.Contains(auditBuf.String(), "inst-2-intruder") {
		t.Fatalf("expected high-severity takeover audit entry, got: %s", auditBuf.String())
	}

	// 4. Revoked JTI must be rejected with 401 on subsequent dial.
	claims, err := signer.Verify(tok)
	if err != nil {
		t.Fatalf("Verify tok: %v", err)
	}
	signer.Revoke(claims.JTI)
	_, respRevoked, err := websocket.Dial(context.Background(), wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + tok}},
	})
	if respRevoked != nil && respRevoked.Body != nil {
		_ = respRevoked.Body.Close()
	}
	if err == nil || (respRevoked != nil && respRevoked.StatusCode != http.StatusUnauthorized) {
		t.Fatalf("expected 401 for revoked token, err=%v resp=%v", err, respRevoked)
	}
}
