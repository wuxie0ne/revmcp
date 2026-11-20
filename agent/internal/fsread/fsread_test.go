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

func TestPathPolicyDenyAllowAndSymlink(t *testing.T) {
	t.Parallel()

	// Default denylist must block high-value paths even before opening them.
	defaultReader := NewReader(DefaultPolicy())
	for _, sensitive := range []string{"/etc/shadow", "/proc/1/environ", "/root/.ssh/id_rsa", "/home/alice/.ssh/id_ed25519"} {
		if _, err := defaultReader.Read(proto.FSReadRequest{Path: sensitive}); !errors.Is(err, ErrPathDenied) {
			t.Fatalf("expected ErrPathDenied for %q, got: %v", sensitive, err)
		}
	}

	// Custom deny + symlink escape attempt must be rejected.
	dir := t.TempDir()
	secretDir := filepath.Join(dir, "secrets")
	publicDir := filepath.Join(dir, "public")
	if err := os.MkdirAll(secretDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(publicDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(secretDir, "key.pem")
	publicFile := filepath.Join(publicDir, "app.log")
	if err := os.WriteFile(secretFile, []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicFile, []byte("OK\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	escapeLink := filepath.Join(publicDir, "escape.log")
	if err := os.Symlink(secretFile, escapeLink); err != nil {
		t.Fatal(err)
	}

	restricted := NewReader(Policy{
		AllowPaths: []string{publicDir + "/*"},
		DenyPaths:  []string{secretDir + "/*"},
	})
	if res, err := restricted.Read(proto.FSReadRequest{Path: publicFile}); err != nil || res.Content != "OK\n" {
		t.Fatalf("expected allowed file read to succeed, res=%+v err=%v", res, err)
	}
	if _, err := restricted.Read(proto.FSReadRequest{Path: secretFile}); !errors.Is(err, ErrPathDenied) {
		t.Fatalf("expected ErrPathDenied for denied file, got: %v", err)
	}
	if _, err := restricted.Read(proto.FSReadRequest{Path: escapeLink}); !errors.Is(err, ErrPathDenied) {
		t.Fatalf("expected ErrPathDenied for symlink escaping into denied/unallowed dir, got: %v", err)
	}

	// NoDefaultDeny disables built-in denylist.
	noDefault := NewReader(Policy{NoDefaultDeny: true})
	if err := noDefault.checkPathPolicy("/etc/shadow"); err != nil {
		t.Fatalf("expected NoDefaultDeny to allow policy check, got: %v", err)
	}
}
