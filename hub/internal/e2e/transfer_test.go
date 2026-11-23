package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/revmcp/revmcp/proto"
)

func checkFileTransfer(t *testing.T, endpoint, bearer, readOnlyBearer, dir string, audit *syncBuffer) {
	t.Helper()
	const target = "e2e-node-01"
	isolated := endpoint + "/mcp/" + target
	path := filepath.Join(dir, "deployment.bin")
	data := bytes.Repeat([]byte{0x00, 0xff, 'X', '\n'}, proto.MaxFileTransferBytes/4)
	hash := proto.FileSHA256(data)
	b64 := base64.StdEncoding.EncodeToString(data)
	call := func(url, token, tool string, args map[string]any) string {
		t.Helper()
		status, body := mcpCall(t, context.Background(), url, token, map[string]any{
			"jsonrpc": "2.0", "method": "tools/call", "id": 1,
			"params": map[string]any{"name": tool, "arguments": args},
		})
		if status != http.StatusOK {
			t.Fatalf("%s returned HTTP %d", tool, status)
		}
		return body
	}
	upload := map[string]any{"path": path, "size": 4, "sha256": hash, "content_base64": "ZmlsZQ=="}
	if got := call(isolated, readOnlyBearer, "upload_file", upload); !strings.Contains(got, "missing required scope") {
		t.Fatalf("expected upload scope denial: %.300s", got)
	}
	if got := call(isolated, bearer, "upload_file", upload); !strings.Contains(got, "SHA-256 does not match") {
		t.Fatalf("expected invalid digest: %.300s", got)
	}

	upload["size"] = len(data)
	upload["content_base64"] = b64
	upload["target_id"] = target
	if got := call(endpoint+"/mcp", bearer, "upload_file", upload); !strings.Contains(got, hash) || strings.Contains(got, `"isError":true`) {
		t.Fatalf("upload at limit failed: %.300s", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, data) {
		t.Fatalf("uploaded file differs: %v", err)
	}
	download := call(isolated, bearer, "download_file", map[string]any{"path": path})
	var result struct {
		Result struct {
			Content []struct {
				Text string
			}
			StructuredContent proto.FileTransferResult
			IsError           bool
		}
	}
	if err := json.Unmarshal([]byte(download), &result); err != nil {
		t.Fatal(err)
	}
	if result.Result.IsError || result.Result.StructuredContent.Size != len(data) ||
		result.Result.StructuredContent.SHA256 != hash || len(result.Result.Content) != 1 ||
		!strings.Contains(result.Result.Content[0].Text, "\n"+b64+"\n</remote_output>") {
		t.Fatalf("download at limit failed: %.300s", download)
	}
	upload = map[string]any{"path": path, "size": 0, "sha256": proto.FileSHA256(nil), "content_base64": ""}
	if got := call(isolated, bearer, "upload_file", upload); !strings.Contains(got, "file already exists") {
		t.Fatalf("expected no overwrite without opt-in: %.300s", got)
	}
	upload["overwrite"] = true
	if got := call(isolated, bearer, "upload_file", upload); strings.Contains(got, `"isError":true`) {
		t.Fatalf("empty file overwrite failed: %.300s", got)
	}
	if stat, err := os.Stat(path); err != nil || stat.Size() != 0 {
		t.Fatalf("empty upload did not overwrite destination: %v", err)
	}
	upload["size"] = proto.MaxFileTransferBytes + 1
	if got := call(isolated, bearer, "upload_file", upload); !strings.Contains(got, "10000000") || !strings.Contains(got, `"isError":true`) {
		t.Fatalf("expected oversized file denial: %.300s", got)
	}
	if log := audit.String(); strings.Contains(log, "content_base64") || strings.Contains(log, b64[:128]) {
		t.Fatal("file content leaked to the audit log")
	}
}
