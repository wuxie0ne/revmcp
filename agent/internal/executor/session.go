package executor

import (
	"context"
	"errors"
	"time"

	"github.com/revmcp/revmcp/proto"
)

// ErrSessionsNotImplemented marks stateful shell sessions as scheduled for Phase 3.
var ErrSessionsNotImplemented = errors.New("executor: stateful shell sessions are not implemented yet")

// SessionConfig bounds persistent shell sessions on the agent.
type SessionConfig struct {
	MaxSessions int
	IdleTimeout time.Duration
}

// SessionPool manages optional stateful shell sessions (full mode only).
type SessionPool struct {
	cfg SessionConfig
}

// NewSessionPool creates a SessionPool with safe defaults.
func NewSessionPool(cfg SessionConfig) *SessionPool {
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 4
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 10 * time.Minute
	}
	return &SessionPool{cfg: cfg}
}

// Open opens a new persistent shell session.
func (p *SessionPool) Open(_ context.Context, _ proto.SessionOpenRequest) (*proto.SessionOpenResult, error) {
	return nil, ErrSessionsNotImplemented
}

// Exec runs a command inside an existing persistent shell session.
func (p *SessionPool) Exec(_ context.Context, _ proto.SessionExecRequest) (*proto.CmdExecResult, error) {
	return nil, ErrSessionsNotImplemented
}

// Close closes a persistent shell session.
func (p *SessionPool) Close(_ context.Context, _ proto.SessionCloseRequest) (*proto.SessionCloseResult, error) {
	return nil, ErrSessionsNotImplemented
}

// CloseAll shuts down all active sessions cleanly.
func (p *SessionPool) CloseAll() {}
