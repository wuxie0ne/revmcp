package fsread

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/revmcp/revmcp/proto"
)

func TestReadChunkAndTail(t *testing.T) {
	t.Parallel()

	p := filepath.Join(t.TempDir(), "app.log")
	lines := make([]string, 0, 50)
	for i := 1; i <= 50; i++ {
		lines = append(lines, "line-"+strings.Repeat("a", 10))
	}
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	zero := int64(0)
	chunk, err := Read(proto.FSReadRequest{Path: p, Offset: &zero, MaxBytes: 64})
	if err != nil {
		t.Fatalf("chunk Read failed: %v", err)
	}
	if !chunk.Truncated || chunk.BytesRead != 64 || chunk.NextOffset != 64 {
		t.Fatalf("unexpected chunk metadata: %+v", chunk)
	}

	tail, err := Read(proto.FSReadRequest{Path: p, TailLines: 5, MaxBytes: 1024})
	if err != nil {
		t.Fatalf("tail Read failed: %v", err)
	}
	gotLines := strings.Split(strings.TrimSuffix(tail.Content, "\n"), "\n")
	if len(gotLines) != 5 {
		t.Fatalf("expected 5 tail lines, got %d: %q", len(gotLines), tail.Content)
	}
}

func TestReadRejectsCharDevice(t *testing.T) {
	t.Parallel()

	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("/dev/zero unavailable")
	}
	if _, err := Read(proto.FSReadRequest{Path: "/dev/zero"}); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("expected ErrInvalidPath for /dev/zero, got: %v", err)
	}
}

func TestGrepBounded(t *testing.T) {
	t.Parallel()

	p := filepath.Join(t.TempDir(), "grep.log")
	data := "info ok\nERROR failed disk\ninfo ok\nERROR timeout\nERROR third\n"
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	res, err := Grep(proto.FSGrepRequest{Path: p, Pattern: "ERROR", MaxMatches: 2})
	if err != nil {
		t.Fatalf("Grep failed: %v", err)
	}
	if !res.Truncated || len(res.Matches) != 2 {
		t.Fatalf("expected 2 truncated matches, got %+v", res)
	}
	if res.Matches[0].LineNumber != 2 || res.Matches[1].LineNumber != 4 {
		t.Fatalf("unexpected match line numbers: %+v", res.Matches)
	}
}
