package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"github.com/revmcp/revmcp/proto"
)

const (
	wsReadLimitBytes = 4 * 1024 * 1024
	initialBackoff   = 1 * time.Second
	maxBackoff       = 30 * time.Second
)

// Handler dispatches a single inbound RPC request from Hub to the local agent engine.
type Handler func(ctx context.Context, req proto.Request) (any, *proto.RPCError)

// Config holds outbound WSS/yamux connection parameters for the agent.
type Config struct {
	HubURL    string
	Token     string
	AgentInfo proto.AgentInfo
	Handler   Handler
	Logger    *slog.Logger
}

// Client manages the persistent outbound tunnel to Hub with exponential backoff reconnect.
type Client struct {
	cfg        Config
	activeRPCs atomic.Int64
}

// NewClient creates a new outbound tunnel client.
func NewClient(cfg Config) *Client {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Client{cfg: cfg}
}

// ActiveRPCs returns the number of currently executing RPC streams.
func (c *Client) ActiveRPCs() int {
	return int(c.activeRPCs.Load())
}

// Run dials Hub and serves RPC streams until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	backoff := initialBackoff

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		err := c.connectAndServe(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
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
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (c *Client) connectAndServe(ctx context.Context) error {
	dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
	defer dialCancel()

	wsConn, resp, err := websocket.Dial(dialCtx, c.cfg.HubURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization": []string{"Bearer " + c.cfg.Token},
		},
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("tunnel: websocket dial: %w", err)
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
		return fmt.Errorf("tunnel: yamux client init: %w", err)
	}
	defer func() { _ = session.Close() }()

	if err := c.register(session); err != nil {
		return fmt.Errorf("tunnel: register: %w", err)
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
				return err
			}
			return fmt.Errorf("tunnel: accept stream: %w", err)
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
