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
	meta, payload, err := proto.EncodeFilePayload(data)
	if err != nil || meta.Encoding != proto.FileEncodingGzip {
		t.Fatalf("encode file: %+v, %v", meta, err)
	}
	b64 := base64.StdEncoding.EncodeToString(payload)
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
	upload := map[string]any{
		"size": 4, "sha256": meta.SHA256, "content_base64": "ZmlsZQ==", "encoding": "identity", "wire_size": 4,
	}
	args := map[string]any{"path": path, "action": "upload", "upload": upload}
	if got := call(isolated, readOnlyBearer, "file", args); !strings.Contains(got, "requires exec:full or exec:session") {
		t.Fatalf("expected upload scope denial: %.300s", got)
	}
	if got := call(isolated, bearer, "file", args); !strings.Contains(got, "SHA-256 does not match") {
		t.Fatalf("expected invalid digest: %.300s", got)
	}

	upload["size"], upload["wire_size"], upload["encoding"] = meta.Size, meta.WireSize, meta.Encoding
	upload["content_base64"] = b64
	args["target_id"] = target
	if got := call(endpoint+"/mcp", bearer, "file", args); !strings.Contains(got, meta.SHA256) || strings.Contains(got, `"isError":true`) {
		t.Fatalf("compressed upload at limit failed: %.300s", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, data) {
		t.Fatalf("uploaded file differs: %v", err)
	}
	download := call(isolated, bearer, "file", map[string]any{"path": path, "action": "download"})
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
	downloadMeta := result.Result.StructuredContent
	if result.Result.IsError || downloadMeta.Size != meta.Size || downloadMeta.SHA256 != meta.SHA256 ||
		downloadMeta.Encoding != proto.FileEncodingGzip || len(result.Result.Content) != 1 {
		t.Fatalf("compressed download at limit failed: %.300s", download)
	}
	_, encoded, opened := strings.Cut(result.Result.Content[0].Text, ">\n")
	encoded, closed := strings.CutSuffix(encoded, "\n</remote_output>")
	if !opened || !closed {
		t.Fatal("download is missing the remote output boundary")
	}
	wire, err := proto.DecodeFileBase64(downloadMeta, encoded)
	if err != nil {
		t.Fatal(err)
	}
	received, err := proto.DecodeFilePayload(downloadMeta, wire)
	if err != nil || !bytes.Equal(received, data) {
		t.Fatalf("downloaded file differs: %v", err)
	}
	upload = map[string]any{
		"size": 0, "sha256": proto.FileSHA256(nil), "content_base64": "", "encoding": "identity", "wire_size": 0,
	}
	args = map[string]any{"path": path, "action": "upload", "upload": upload}
	if got := call(isolated, bearer, "file", args); !strings.Contains(got, "file already exists") {
		t.Fatalf("expected no overwrite without opt-in: %.300s", got)
	}
	upload["overwrite"] = true
	if got := call(isolated, bearer, "file", args); strings.Contains(got, `"isError":true`) {
		t.Fatalf("empty file overwrite failed: %.300s", got)
	}
	if stat, err := os.Stat(path); err != nil || stat.Size() != 0 {
		t.Fatalf("empty upload did not overwrite destination: %v", err)
	}
	upload["size"] = proto.MaxFileTransferBytes + 1
	if got := call(isolated, bearer, "file", args); !strings.Contains(got, "10000000") || !strings.Contains(got, `"isError":true`) {
		t.Fatalf("expected oversized file denial: %.300s", got)
	}
	if log := audit.String(); strings.Contains(log, "content_base64") || strings.Contains(log, b64[:128]) {
		t.Fatal("file content leaked to the audit log")
	}
}
