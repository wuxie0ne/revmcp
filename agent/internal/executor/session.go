package executor

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/revmcp/revmcp/proto"
)

var (
	// ErrSessionNotFound indicates the requested session ID does not exist or was reaped.
	ErrSessionNotFound = errors.New("executor: session not found")
	// ErrMaxSessionsReached indicates the pool reached MaxSessions.
	ErrMaxSessionsReached = errors.New("executor: maximum concurrent shell sessions reached")
	// ErrSessionClosed indicates the shell process terminated unexpectedly.
	ErrSessionClosed = errors.New("executor: shell session closed")
)

// SessionConfig bounds persistent shell sessions on the agent.
type SessionConfig struct {
	MaxSessions int
	IdleTimeout time.Duration
	ShellPath   string
}

type shellSession struct {
	id         string
	cmd        *exec.Cmd
	pid        int
	stdin      io.WriteCloser
	stdoutPipe *os.File
	reader     *bufio.Reader
	doneCh     chan struct{}

	execMu   sync.Mutex
	stateMu  sync.Mutex
	lastUsed time.Time
	inUse    bool
	closed   bool
}

// SessionPool manages optional stateful shell sessions (full mode only) with
// max-session bounds, idle reaping, process-group cleanup, and zero zombie processes.
type SessionPool struct {
	cfg      SessionConfig
	mu       sync.Mutex
	sessions map[string]*shellSession
	stopCh   chan struct{}
	stopOnce sync.Once
	reaperWg sync.WaitGroup
}

// NewSessionPool creates a SessionPool with safe defaults and starts its idle reaper.
func NewSessionPool(cfg SessionConfig) *SessionPool {
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 4
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 10 * time.Minute
	}
	if cfg.ShellPath == "" {
		cfg.ShellPath = ResolveShell()
	}

	p := &SessionPool{
		cfg:      cfg,
		sessions: make(map[string]*shellSession),
		stopCh:   make(chan struct{}),
	}

	interval := cfg.IdleTimeout / 2
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	if interval < 25*time.Millisecond {
		interval = 25 * time.Millisecond
	}

	p.reaperWg.Add(1)
	go p.reapLoop(interval)
	return p
}

// Open spawns a new persistent non-interactive shell session.
func (p *SessionPool) Open(_ context.Context, req proto.SessionOpenRequest) (*proto.SessionOpenResult, error) {
	p.mu.Lock()
	if len(p.sessions) >= p.cfg.MaxSessions {
		p.mu.Unlock()
		return nil, fmt.Errorf("%w (max=%d)", ErrMaxSessionsReached, p.cfg.MaxSessions)
	}
	p.mu.Unlock()

	sess, err := p.spawnSession(req.Workdir)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	if len(p.sessions) >= p.cfg.MaxSessions {
		p.mu.Unlock()
		sess.terminate()
		return nil, fmt.Errorf("%w (max=%d)", ErrMaxSessionsReached, p.cfg.MaxSessions)
	}
	p.sessions[sess.id] = sess
	p.mu.Unlock()

	return &proto.SessionOpenResult{SessionID: sess.id}, nil
}

// Exec runs a command inside an existing persistent shell session, preserving cwd and env vars.
func (p *SessionPool) Exec(ctx context.Context, req proto.SessionExecRequest) (*proto.CmdExecResult, error) {
	if strings.TrimSpace(req.SessionID) == "" {
		return nil, fmt.Errorf("%w: empty session_id", ErrSessionNotFound)
	}
	if strings.TrimSpace(req.Command) == "" {
		return nil, errors.New("executor: empty command")
	}

	p.mu.Lock()
	sess, ok := p.sessions[req.SessionID]
	p.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSessionNotFound, req.SessionID)
	}

	timeout := DefaultTimeout
	if req.TimeoutSec > 0 {
		timeout = time.Duration(req.TimeoutSec) * time.Second
		if timeout > MaxTimeout {
			timeout = MaxTimeout
		}
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	res, fatal, err := sess.exec(execCtx, req.Command, req.MaxBytes)
	if fatal {
		p.removeSession(sess.id, sess)
		sess.terminate()
	}
	return res, err
}

// Close terminates and removes a persistent shell session.
func (p *SessionPool) Close(_ context.Context, req proto.SessionCloseRequest) (*proto.SessionCloseResult, error) {
	if strings.TrimSpace(req.SessionID) == "" {
		return nil, fmt.Errorf("%w: empty session_id", ErrSessionNotFound)
	}

	p.mu.Lock()
	sess, ok := p.sessions[req.SessionID]
	if ok {
		delete(p.sessions, req.SessionID)
	}
	p.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSessionNotFound, req.SessionID)
	}
	sess.terminate()
	return &proto.SessionCloseResult{Closed: true}, nil
}

// ActiveCount returns the number of live sessions currently tracked by the pool.
func (p *SessionPool) ActiveCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sessions)
}

// CloseAll stops the idle reaper and terminates all active sessions cleanly.
func (p *SessionPool) CloseAll() {
	p.stopOnce.Do(func() {
		close(p.stopCh)
	})
	p.reaperWg.Wait()

	p.mu.Lock()
	all := make([]*shellSession, 0, len(p.sessions))
	for id, s := range p.sessions {
		all = append(all, s)
		delete(p.sessions, id)
	}
	p.mu.Unlock()

	for _, s := range all {
		s.terminate()
	}
}

func (p *SessionPool) removeSession(id string, target *shellSession) {
	p.mu.Lock()
	if cur, ok := p.sessions[id]; ok && cur == target {
		delete(p.sessions, id)
	}
	p.mu.Unlock()
}

func (p *SessionPool) reapLoop(interval time.Duration) {
	defer p.reaperWg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.reapIdle()
		}
	}
}

func (p *SessionPool) reapIdle() {
	now := time.Now()
	var expired []*shellSession

	p.mu.Lock()
	for id, s := range p.sessions {
		s.stateMu.Lock()
		isDead := s.closed
		isIdle := !s.inUse && now.Sub(s.lastUsed) >= p.cfg.IdleTimeout
		s.stateMu.Unlock()

		if isDead || isIdle {
			delete(p.sessions, id)
			expired = append(expired, s)
		}
	}
	p.mu.Unlock()

	for _, s := range expired {
		s.terminate()
	}
}

func (p *SessionPool) spawnSession(workdir string) (*shellSession, error) {
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("executor: create session pipe: %w", err)
	}

	cmd := exec.Command(p.cfg.ShellPath)
	if workdir != "" {
		cmd.Dir = workdir
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"GIT_TERMINAL_PROMPT=0",
		"PAGER=cat",
		"PS1=",
		"PS2=",
	)
	cmd.Stdout = pw
	cmd.Stderr = pw

	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, fmt.Errorf("executor: session stdin pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = pr.Close()
		_ = pw.Close()
		return nil, fmt.Errorf("executor: start session shell: %w", err)
	}
	// Close parent's write end so pr observes EOF once the shell process group exits.
	_ = pw.Close()

	sess := &shellSession{
		id:         newSessionID(),
		cmd:        cmd,
		pid:        cmd.Process.Pid,
		stdin:      stdin,
		stdoutPipe: pr,
		reader:     bufio.NewReaderSize(pr, 32*1024),
		doneCh:     make(chan struct{}),
		lastUsed:   time.Now(),
	}

	// Always reap the child process to prevent zombies.
	go func() {
		_ = cmd.Wait()
		sess.stateMu.Lock()
		sess.closed = true
		sess.stateMu.Unlock()
		close(sess.doneCh)
	}()

	return sess, nil
}

func (s *shellSession) exec(ctx context.Context, command string, maxBytes int) (*proto.CmdExecResult, bool, error) {
	s.execMu.Lock()
	defer s.execMu.Unlock()

	s.stateMu.Lock()
	if s.closed {
		s.stateMu.Unlock()
		return nil, true, ErrSessionClosed
	}
	s.inUse = true
	s.lastUsed = time.Now()
	s.stateMu.Unlock()

	defer func() {
		s.stateMu.Lock()
		s.inUse = false
		s.lastUsed = time.Now()
		s.stateMu.Unlock()
	}()

	sentinel := "__REVMCP_DONE_" + newSessionID() + "__"
	sentinelPrefix := sentinel + ":"
	// Execute user command in the current shell context so cd/export persist,
	// then emit the unique sentinel line carrying the exit status.
	script := fmt.Sprintf("%s\n__revmcp_ec=$?\nprintf '\\n%s%%d\\n' \"$__revmcp_ec\"\n", command, sentinelPrefix)

	start := time.Now()
	if _, err := io.WriteString(s.stdin, script); err != nil {
		return nil, true, fmt.Errorf("%w: write command: %v", ErrSessionClosed, err)
	}

	buf := NewHeadTailBuffer(maxBytes)

	type readOutcome struct {
		exitCode int
		err      error
	}
	outcomeCh := make(chan readOutcome, 1)

	go func() {
		for {
			line, err := s.reader.ReadString('\n')
			if len(line) > 0 {
				trimmed := strings.TrimRight(line, "\r\n")
				if strings.HasPrefix(trimmed, sentinelPrefix) {
					codeStr := strings.TrimPrefix(trimmed, sentinelPrefix)
					ec, parseErr := strconv.Atoi(strings.TrimSpace(codeStr))
					if parseErr != nil {
						ec = -1
					}
					outcomeCh <- readOutcome{exitCode: ec}
					return
				}
				_, _ = buf.Write([]byte(line))
			}
			if err != nil {
				outcomeCh <- readOutcome{exitCode: -1, err: err}
				return
			}
		}
	}()

	select {
	case out := <-outcomeCh:
		duration := time.Since(start)
		if out.err != nil {
			return &proto.CmdExecResult{
				ExitCode:   -1,
				Output:     buf.String(),
				Truncated:  buf.Truncated(),
				Dropped:    buf.Dropped(),
				DurationMS: duration.Milliseconds(),
			}, true, fmt.Errorf("%w: %v", ErrSessionClosed, out.err)
		}
		return &proto.CmdExecResult{
			ExitCode:   out.exitCode,
			Output:     strings.TrimSuffix(buf.String(), "\n"),
			Truncated:  buf.Truncated(),
			Dropped:    buf.Dropped(),
			DurationMS: duration.Milliseconds(),
		}, false, nil

	case <-ctx.Done():
		timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
		// Kill entire process group so hanging commands/children inside the session cannot survive.
		s.terminate()
		<-outcomeCh
		return &proto.CmdExecResult{
			ExitCode:   -1,
			Output:     buf.String(),
			Truncated:  buf.Truncated(),
			Dropped:    buf.Dropped(),
			TimedOut:   timedOut,
			DurationMS: time.Since(start).Milliseconds(),
		}, true, nil
	}
}

func (s *shellSession) terminate() {
	s.stateMu.Lock()
	s.closed = true
	s.stateMu.Unlock()

	_ = s.stdin.Close()
	if s.pid > 0 {
		_ = syscall.Kill(-s.pid, syscall.SIGKILL)
	}
	<-s.doneCh
	_ = s.stdoutPipe.Close()
}

func newSessionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("s%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
