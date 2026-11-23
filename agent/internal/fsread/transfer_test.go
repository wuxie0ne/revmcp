package fsread

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/revmcp/revmcp/proto"
)

func TestTransferPathBoundaries(t *testing.T) {
	ctx := context.Background()
	dir, outside := t.TempDir(), t.TempDir()
	data := []byte("test content")
	existing := filepath.Join(outside, "existing")
	if err := os.WriteFile(existing, data, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "symlink")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	reader := NewReader(Policy{AllowPaths: []string{dir}, DenyPaths: []string{filepath.Join(dir, "denied")}})
	if _, err := reader.Download(ctx, existing); !errors.Is(err, ErrPathDenied) {
		t.Fatalf("download outside allowed paths: %v", err)
	}
	for _, path := range []string{fifo, link, filepath.Join(link, "existing")} {
		if _, err := reader.Download(ctx, path); err == nil {
			t.Errorf("download unexpectedly permitted: %s", path)
		}
	}
	meta, payload, err := proto.EncodeFilePayload(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, link, filepath.Join(link, "existing"), filepath.Join(dir, "denied")} {
		req := proto.FSUploadRequest{Path: path, FileTransferResult: meta, Overwrite: true}
		if _, err := reader.Upload(ctx, req, payload); err == nil {
			t.Errorf("upload unexpectedly permitted: %s", path)
		}
	}
	if _, err := reader.Upload(ctx, proto.FSUploadRequest{Path: existing, FileTransferResult: meta, Overwrite: true}, payload); err != nil {
		t.Fatalf("upload should use filesystem permissions independently of the read allowlist: %v", err)
	}

	dest := filepath.Join(dir, "new-file")
	req := proto.FSUploadRequest{Path: dest, FileTransferResult: meta}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := reader.Upload(cancelled, req, payload); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected cancelled upload result: %v", err)
	}
	if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled upload created the destination: %v", err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 2 {
		t.Fatalf("cancelled upload left staging files: %v %v", entries, err)
	}
}
