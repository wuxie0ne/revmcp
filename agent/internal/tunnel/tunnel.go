package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"github.com/revmcp/revmcp/proto"
)

const (
	wsReadLimitBytes      = 4 * 1024 * 1024
	defaultInitialBackoff = 1 * time.Second
	defaultMaxBackoff     = 30 * time.Second
)

// Handler dispatches a single inbound RPC request from Hub to the local agent engine.
type Handler func(ctx context.Context, req proto.Request) (any, *proto.RPCError)

// Config holds outbound WSS/WS + yamux connection parameters for the agent.
type Config struct {
	HubURL         string
	Token          string
	CACertPath     string
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	AgentInfo      proto.AgentInfo
	Handler        Handler
	Logger         *slog.Logger
}

// Client manages the persistent outbound tunnel to Hub with exponential backoff reconnect.
type Client struct {
	cfg        Config
	httpClient *http.Client
	activeRPCs atomic.Int64
}

// NewClient creates a new outbound tunnel client, optionally loading a custom CA bundle
// while preserving standard HTTPS_PROXY / HTTP_PROXY environment support.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = defaultInitialBackoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = defaultMaxBackoff
	}

	httpClient, err := buildHTTPClient(cfg.CACertPath)
	if err != nil {
		return nil, err
	}

	return &Client{
		cfg:        cfg,
		httpClient: httpClient,
	}, nil
}

func buildHTTPClient(caCertPath string) (*http.Client, error) {
	if caCertPath == "" {
		return nil, nil
	}

	pemData, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("tunnel: read ca-cert %q: %w", caCertPath, err)
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("tunnel: no valid PEM certificates found in %q", caCertPath)
	}

	base, ok := http.DefaultTransport.(*http.Transport)
	var tr *http.Transport
	if ok {
		tr = base.Clone()
	} else {
		tr = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	}
	tr.TLSClientConfig.RootCAs = pool

	return &http.Client{Transport: tr}, nil
}

// ActiveRPCs returns the number of currently executing RPC streams.
func (c *Client) ActiveRPCs() int {
	return int(c.activeRPCs.Load())
}

// Run dials Hub (ws:// or wss:// on any configured port) and serves RPC streams until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	backoff := c.cfg.InitialBackoff

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		registered, err := c.connectAndServe(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if registered {
			// Reset backoff after a session successfully registered so transient drops recover quickly.
			backoff = c.cfg.InitialBackoff
		}

		c.cfg.Logger.Warn("tunnel disconnected, reconnecting", "err", err, "backoff", backoff)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}

		backoff *= 2
		if backoff > c.cfg.MaxBackoff {
			backoff = c.cfg.MaxBackoff
		}
	}
}

func (c *Client) connectAndServe(ctx context.Context) (bool, error) {
	dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
	defer dialCancel()

	dialOpts := &websocket.DialOptions{
		HTTPClient: c.httpClient,
		HTTPHeader: http.Header{
			"Authorization": []string{"Bearer " + c.cfg.Token},
		},
	}

	wsConn, resp, err := websocket.Dial(dialCtx, c.cfg.HubURL, dialOpts)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return false, fmt.Errorf("tunnel: websocket dial: %w", err)
	}

	// Critical rule: raise ReadLimit from default 32KB to 4MB before wrapping in NetConn.
	wsConn.SetReadLimit(wsReadLimitBytes)

	// Critical rule: use a dedicated connection lifecycle context, never a request context.
	connCtx, connCancel := context.WithCancel(context.Background())
	defer connCancel()

	netConn := websocket.NetConn(connCtx, wsConn, websocket.MessageBinary)
	defer func() {
		_ = netConn.Close()
		_ = wsConn.Close(websocket.StatusNormalClosure, "shutdown")
	}()

	yCfg := yamux.DefaultConfig()
	yCfg.EnableKeepAlive = true
	yCfg.KeepAliveInterval = 10 * time.Second
	yCfg.ConnectionWriteTimeout = 15 * time.Second
	yCfg.LogOutput = io.Discard

	session, err := yamux.Client(netConn, yCfg)
	if err != nil {
		return false, fmt.Errorf("tunnel: yamux client init: %w", err)
	}
	defer func() { _ = session.Close() }()

	if err := c.register(session); err != nil {
		return false, fmt.Errorf("tunnel: register: %w", err)
	}
	c.cfg.Logger.Info("agent registered with hub", "target_id", c.cfg.AgentInfo.TargetID, "mode", c.cfg.AgentInfo.Mode)

	// Close session when parent context is cancelled.
	go func() {
		<-ctx.Done()
		_ = session.Close()
		connCancel()
	}()

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return true, err
			}
			return true, fmt.Errorf("tunnel: accept stream: %w", err)
		}
		go c.handleStream(ctx, stream)
	}
}

func (c *Client) register(session *yamux.Session) error {
	stream, err := session.OpenStream()
	if err != nil {
		return err
	}
	defer func() { _ = stream.Close() }()

	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))

	params, err := json.Marshal(proto.RegisterRequest{
		ProtoVersion: proto.ProtocolVersion,
		Agent:        c.cfg.AgentInfo,
	})
	if err != nil {
		return err
	}

	req := proto.Request{
		ID:     "register",
		Method: proto.MethodAgentRegister,
		Params: params,
	}
	if err := proto.WriteFrame(stream, req); err != nil {
		return err
	}

	var resp proto.Response
	if err := proto.ReadFrame(stream, &resp); err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error
	}

	var regResp proto.RegisterResponse
	if err := json.Unmarshal(resp.Result, &regResp); err != nil {
		return err
	}
	if !regResp.Accepted {
		return fmt.Errorf("registration rejected: %s", regResp.Message)
	}
	return nil
}

func (c *Client) handleStream(parentCtx context.Context, stream *yamux.Stream) {
	defer func() { _ = stream.Close() }()

	c.activeRPCs.Add(1)
	defer c.activeRPCs.Add(-1)

	var req proto.Request
	if err := proto.ReadFrame(stream, &req); err != nil {
		return
	}

	rpcCtx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	// Watch for Hub closing/resetting the stream to immediately propagate cancellation.
	go func() {
		var b [1]byte
		if _, err := stream.Read(b[:]); err != nil {
			cancel()
		}
	}()

	c.cfg.Logger.Debug("dispatching rpc", "method", req.Method, "req_id", req.ID, "trace_id", req.TraceID)

	result, rpcErr := c.cfg.Handler(rpcCtx, req)
	resp := proto.Response{
		ID:    req.ID,
		Error: rpcErr,
	}
	if rpcErr == nil && result != nil {
		raw, err := json.Marshal(result)
		if err != nil {
			resp.Error = &proto.RPCError{
				Code:    proto.ErrCodeInternal,
				Message: fmt.Sprintf("marshal result: %v", err),
			}
		} else {
			resp.Result = raw
		}
	}

	_ = proto.WriteFrame(stream, resp)
}
