package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/revmcp/revmcp/proto"
)

func TestSessionPoolPreservesCwdAndEnv(t *testing.T) {
	t.Parallel()

	pool := NewSessionPool(SessionConfig{MaxSessions: 2, IdleTimeout: time.Minute})
	defer pool.CloseAll()

	dir := t.TempDir()
	opened, err := pool.Open(context.Background(), proto.SessionOpenRequest{Workdir: dir})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	subDir := filepath.Join(dir, "sub")
	if err := os.MkdirAll(subDir, 0o700); err != nil {
		t.Fatal(err)
	}

	res1, err := pool.Exec(context.Background(), proto.SessionExecRequest{
		SessionID: opened.SessionID,
		Command:   "cd sub && export REVMCP_VAR=hello_world",
	})
	if err != nil || res1.ExitCode != 0 {
		t.Fatalf("Exec 1 failed: res=%+v err=%v", res1, err)
	}

	res2, err := pool.Exec(context.Background(), proto.SessionExecRequest{
		SessionID: opened.SessionID,
		Command:   `pwd && echo "$REVMCP_VAR"`,
	})
	if err != nil || res2.ExitCode != 0 {
		t.Fatalf("Exec 2 failed: res=%+v err=%v", res2, err)
	}
	if !strings.Contains(res2.Output, subDir) || !strings.Contains(res2.Output, "hello_world") {
		t.Fatalf("expected persisted cwd and env var, got: %q", res2.Output)
	}

	// Non-zero exit code must be accurately captured without killing session.
	res3, err := pool.Exec(context.Background(), proto.SessionExecRequest{
		SessionID: opened.SessionID,
		Command:   "(exit 42)",
	})
	if err != nil || res3.ExitCode != 42 {
		t.Fatalf("expected exit code 42, got res=%+v err=%v", res3, err)
	}

	// Session remains usable after non-zero exit code.
	res4, err := pool.Exec(context.Background(), proto.SessionExecRequest{
		SessionID: opened.SessionID,
		Command:   "echo still_alive",
	})
	if err != nil || res4.ExitCode != 0 || !strings.Contains(res4.Output, "still_alive") {
		t.Fatalf("expected session still alive, got res=%+v err=%v", res4, err)
	}

	if _, err := pool.Close(context.Background(), proto.SessionCloseRequest{SessionID: opened.SessionID}); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if pool.ActiveCount() != 0 {
		t.Fatalf("expected 0 active sessions after close, got %d", pool.ActiveCount())
	}
}

func TestSessionPoolMaxLimitIdleReapAndNoZombies(t *testing.T) {
	t.Parallel()

	pool := NewSessionPool(SessionConfig{MaxSessions: 1, IdleTimeout: 150 * time.Millisecond})
	defer pool.CloseAll()

	s1, err := pool.Open(context.Background(), proto.SessionOpenRequest{})
	if err != nil {
		t.Fatalf("Open s1 failed: %v", err)
	}
	if _, err := pool.Open(context.Background(), proto.SessionOpenRequest{}); !errors.Is(err, ErrMaxSessionsReached) {
		t.Fatalf("expected ErrMaxSessionsReached, got: %v", err)
	}

	// Capture the shell PID so we can verify idle reaping kills and reaps it completely.
	res, err := pool.Exec(context.Background(), proto.SessionExecRequest{
		SessionID: s1.SessionID,
		Command:   "echo $$",
	})
	if err != nil {
		t.Fatalf("Exec pid failed: %v", err)
	}
	shellPID, err := strconv.Atoi(strings.TrimSpace(res.Output))
	if err != nil || shellPID <= 0 {
		t.Fatalf("invalid shell PID %q: %v", res.Output, err)
	}

	// Wait for idle timeout reaper to kill and reap the shell process.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pool.ActiveCount() == 0 && syscall.Kill(shellPID, 0) == syscall.ESRCH {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("idle session was not reaped cleanly: active=%d pid=%d", pool.ActiveCount(), shellPID)
}

func TestSessionTimeoutKillsProcessGroupNoOrphans(t *testing.T) {
	t.Parallel()

	pool := NewSessionPool(SessionConfig{MaxSessions: 2, IdleTimeout: time.Minute})
	defer pool.CloseAll()

	s, err := pool.Open(context.Background(), proto.SessionOpenRequest{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	pidFile := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	res, err := pool.Exec(ctx, proto.SessionExecRequest{
		SessionID:  s.SessionID,
		Command:    "sleep 30 & echo $! > " + pidFile + "; wait",
		TimeoutSec: 5,
	})
	if err != nil {
		t.Fatalf("Exec returned unexpected error: %v", err)
	}
	if !res.TimedOut {
		t.Fatalf("expected TimedOut=true, got %+v", res)
	}
	if pool.ActiveCount() != 0 {
		t.Fatalf("expected killed session to be evicted from pool, active=%d", pool.ActiveCount())
	}

	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read child pid file: %v", err)
	}
	childPID, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || childPID <= 0 {
		t.Fatalf("invalid child PID %q", string(data))
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if syscall.Kill(childPID, 0) == syscall.ESRCH {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("orphan child process %d still alive after session timeout", childPID)
}
