package tunnel

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"github.com/revmcp/revmcp/proto"
)

func acceptMockHubSession(t *testing.T, w http.ResponseWriter, r *http.Request) (*yamux.Session, context.CancelFunc, func()) {
	t.Helper()
	wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		t.Errorf("websocket.Accept failed: %v", err)
		return nil, nil, nil
	}
	wsConn.SetReadLimit(wsReadLimitBytes)
	connCtx, connCancel := context.WithCancel(context.Background())
	netConn := websocket.NetConn(connCtx, wsConn, websocket.MessageBinary)

	yCfg := yamux.DefaultConfig()
	yCfg.LogOutput = io.Discard
	sess, err := yamux.Server(netConn, yCfg)
	if err != nil {
		connCancel()
		t.Errorf("yamux.Server failed: %v", err)
		return nil, nil, nil
	}

	regStream, err := sess.AcceptStream()
	if err != nil {
		_ = sess.Close()
		connCancel()
		t.Errorf("AcceptStream(register) failed: %v", err)
		return nil, nil, nil
	}
	var regReq proto.Request
	if err := proto.ReadFrame(regStream, &regReq); err != nil {
		t.Errorf("ReadFrame(register) failed: %v", err)
	}
	raw, _ := json.Marshal(proto.RegisterResponse{Accepted: true, HubVersion: "test"})
	_ = proto.WriteFrame(regStream, proto.Response{ID: regReq.ID, Result: raw})
	_ = regStream.Close()

	cleanup := func() {
		_ = sess.Close()
		connCancel()
		_ = wsConn.Close(websocket.StatusNormalClosure, "done")
	}
	return sess, connCancel, cleanup
}

func TestClientReconnectAndCascadeCancel(t *testing.T) {
	t.Parallel()

	var connections atomic.Int32
	canceledCh := make(chan struct{}, 1)
	rpcDoneCh := make(chan string, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := connections.Add(1)
		sess, _, cleanup := acceptMockHubSession(t, w, r)
		if sess == nil {
			return
		}
		defer cleanup()

		if n == 1 {
			// Drop first connection immediately to verify automatic reconnect.
			return
		}

		// Second connection: send a ping RPC and verify round-trip, then test stream-close cancellation.
		st, err := sess.OpenStream()
		if err != nil {
			t.Errorf("OpenStream ping failed: %v", err)
			return
		}
		_ = proto.WriteFrame(st, proto.Request{ID: "r1", TraceID: "tr-1", Method: proto.MethodAgentPing})
		var resp proto.Response
		if err := proto.ReadFrame(st, &resp); err != nil {
			t.Errorf("ReadFrame ping failed: %v", err)
		}
		_ = st.Close()
		rpcDoneCh <- resp.ID

		// Open a blocking RPC and close the stream from Hub side to verify cascade cancel.
		st2, err := sess.OpenStream()
		if err != nil {
			t.Errorf("OpenStream block failed: %v", err)
			return
		}
		_ = proto.WriteFrame(st2, proto.Request{ID: "r2", Method: "test.block"})
		time.Sleep(80 * time.Millisecond)
		_ = st2.Close()

		<-sess.CloseChan()
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/agent/ws"
	client, err := NewClient(Config{
		HubURL:         wsURL,
		Token:          "tok",
		InitialBackoff: 30 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
		AgentInfo:      proto.AgentInfo{TargetID: "t1", Mode: proto.ModeReadOnly},
		Handler: func(ctx context.Context, req proto.Request) (any, *proto.RPCError) {
			if req.Method == "test.block" {
				<-ctx.Done()
				canceledCh <- struct{}{}
				return nil, &proto.RPCError{Code: proto.ErrCodeCancelled, Message: "cancelled"}
			}
			return &proto.PingResult{UptimeSeconds: 1}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = client.Run(ctx) }()

	select {
	case id := <-rpcDoneCh:
		if id != "r1" {
			t.Fatalf("unexpected ping response id %q", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for reconnect + ping RPC")
	}

	select {
	case <-canceledCh:
	case <-time.After(2 * time.Second):
		t.Fatal("expected handler context to be cancelled promptly when Hub closed stream")
	}

	if connections.Load() < 2 {
		t.Fatalf("expected at least 2 connections (reconnect), got %d", connections.Load())
	}
}

func TestClientCustomCACertWSS(t *testing.T) {
	t.Parallel()

	connected := make(chan struct{}, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _, cleanup := acceptMockHubSession(t, w, r)
		if sess == nil {
			return
		}
		defer cleanup()
		connected <- struct{}{}
		<-sess.CloseChan()
	}))
	defer srv.Close()

	// Write the test server's self-signed certificate to a PEM file.
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write ca.pem: %v", err)
	}

	wssURL := "wss" + strings.TrimPrefix(srv.URL, "https") + "/agent/ws"
	client, err := NewClient(Config{
		HubURL:         wssURL,
		Token:          "tok",
		CACertPath:     caPath,
		InitialBackoff: 50 * time.Millisecond,
		AgentInfo:      proto.AgentInfo{TargetID: "tls-node", Mode: proto.ModeReadOnly},
		Handler: func(_ context.Context, _ proto.Request) (any, *proto.RPCError) {
			return &proto.PingResult{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewClient with CACertPath failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = client.Run(ctx) }()

	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out connecting over WSS with custom --ca-cert")
	}
}
