package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/revmcp/revmcp/proto"
)

const (
	DefaultTimeout = 30 * time.Second
	MaxTimeout     = 120 * time.Second
)

// Executor runs non-interactive commands with process-group isolation and bounded output.
type Executor struct {
	shellPath string
}

// New creates an Executor, probing /bin/bash and falling back to /bin/sh.
func New() *Executor {
	return &Executor{shellPath: ResolveShell()}
}

// ResolveShell probes /bin/bash and falls back to /bin/sh for minimal containers.
func ResolveShell() string {
	if fi, err := os.Stat("/bin/bash"); err == nil && !fi.IsDir() {
		return "/bin/bash"
	}
	return "/bin/sh"
}

// Exec executes a single non-interactive command, killing its entire process group on
// timeout or context cancellation and capping combined output via HeadTailBuffer.
func (e *Executor) Exec(ctx context.Context, req proto.CmdExecRequest) (*proto.CmdExecResult, error) {
	timeout := DefaultTimeout
	if req.TimeoutSec > 0 {
		timeout = time.Duration(req.TimeoutSec) * time.Second
		if timeout > MaxTimeout {
			timeout = MaxTimeout
		}
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.Command(e.shellPath, "-c", req.Command)
	cmd.Stdin = nil
	if req.Workdir != "" {
		cmd.Dir = req.Workdir
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"GIT_TERMINAL_PROMPT=0",
		"PAGER=cat",
	)

	buf := NewHeadTailBuffer(req.MaxBytes)
	cmd.Stdout = buf
	cmd.Stderr = buf

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("executor: start command: %w", err)
	}

	pid := cmd.Process.Pid
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	var waitErr error
	var timedOut bool

	select {
	case waitErr = <-waitCh:
	case <-execCtx.Done():
		timedOut = errors.Is(execCtx.Err(), context.DeadlineExceeded)
		// Kill the entire process group (negative PID) so child processes cannot leak as orphans.
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		waitErr = <-waitCh
	}

	duration := time.Since(start)
	exitCode := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return &proto.CmdExecResult{
		ExitCode:   exitCode,
		Output:     buf.String(),
		Truncated:  buf.Truncated(),
		Dropped:    buf.Dropped(),
		TimedOut:   timedOut,
		DurationMS: duration.Milliseconds(),
	}, nil
}
