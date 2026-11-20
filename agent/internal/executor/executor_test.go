package executor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/revmcp/revmcp/proto"
)

func TestHeadTailBufferLargeOutput(t *testing.T) {
	t.Parallel()

	const maxCap = 4096
	buf := NewHeadTailBuffer(maxCap)

	headMarker := "HEAD-START-MARKER\n"
	tailMarker := "\nTAIL-END-MARKER"

	if _, err := buf.Write([]byte(headMarker)); err != nil {
		t.Fatalf("write head failed: %v", err)
	}

	// Write > 1 MiB of middle noise in chunks.
	chunk := bytes.Repeat([]byte("x"), 16*1024)
	for i := 0; i < 80; i++ {
		if _, err := buf.Write(chunk); err != nil {
			t.Fatalf("write chunk %d failed: %v", i, err)
		}
	}

	if _, err := buf.Write([]byte(tailMarker)); err != nil {
		t.Fatalf("write tail failed: %v", err)
	}

	if !buf.Truncated() {
		t.Fatal("expected buffer to report Truncated() == true")
	}
	if buf.Dropped() < 1024*1024 {
		t.Fatalf("expected > 1 MiB dropped, got %d", buf.Dropped())
	}

	out := buf.String()
	if !strings.HasPrefix(out, headMarker) {
		t.Fatalf("expected output to preserve head marker")
	}
	if !strings.HasSuffix(out, tailMarker) {
		t.Fatalf("expected output to preserve tail marker")
	}
	if !strings.Contains(out, "[truncated ") {
		t.Fatalf("expected truncation notice in output")
	}
	if len(out) > maxCap+256 {
		t.Fatalf("output size exceeded expected bound: %d", len(out))
	}
}

func TestExecutorTimeoutKillsProcessGroupNoOrphans(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "child.pid")

	// Spawn a background child process, record its PID, and block until killed.
	cmd := "sleep 30 & echo $! > " + pidFile + "; wait"

	execEngine := New()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	res, err := execEngine.Exec(ctx, proto.CmdExecRequest{
		Command:    cmd,
		TimeoutSec: 5,
	})
	if err != nil {
		t.Fatalf("Exec returned unexpected error: %v", err)
	}
	if !res.TimedOut {
		t.Fatalf("expected TimedOut=true, got %+v", res)
	}

	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("expected child PID file to exist: %v", err)
	}
	childPID, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || childPID <= 0 {
		t.Fatalf("invalid child PID %q: %v", string(data), err)
	}

	// Poll briefly to confirm the child process is completely gone (no orphan).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		err := syscall.Kill(childPID, 0)
		if err == syscall.ESRCH {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("orphan child process %d is still alive after timeout kill", childPID)
}

func TestExecutorCancelKillsProcessGroup(t *testing.T) {
	t.Parallel()

	execEngine := New()
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	res, err := execEngine.Exec(ctx, proto.CmdExecRequest{
		Command:    "sleep 30",
		TimeoutSec: 10,
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Exec returned unexpected error: %v", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code on cancellation, got 0")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected prompt cancellation, took %v", elapsed)
	}
}
