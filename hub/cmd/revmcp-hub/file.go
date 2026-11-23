package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/revmcp/revmcp/proto"
)

type bearerTransport struct {
	token string
}

func (t bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+t.token)
	resp, err := http.DefaultTransport.RoundTrip(clone)
	if err == nil {
		resp.Body = http.MaxBytesReader(nil, resp.Body, 14*1024*1024)
	}
	return resp, err
}

func runFile(args []string) error {
	if len(args) == 0 || (args[0] != "upload" && args[0] != "download") {
		return errors.New("expected subcommand: file upload | download")
	}
	action := args[0]
	flags := flag.NewFlagSet("file "+action, flag.ContinueOnError)
	endpoint := flags.String("endpoint", "", "Hub MCP endpoint URL")
	target := flags.String("target", "", "Target ID when using the aggregated /mcp endpoint")
	local := flags.String("local", "", "Local file path")
	remote := flags.String("remote", "", "Absolute remote file path")
	overwrite := flags.Bool("overwrite", false, "Replace the destination file if it already exists")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *local == "" || *remote == "" || flags.NArg() != 0 {
		return errors.New("--local and --remote are required")
	}
	if err := checkFileEndpoint(*endpoint, *target); err != nil {
		return err
	}
	token := os.Getenv("REVMCP_BEARER_TOKEN")
	if token == "" {
		return errors.New("REVMCP_BEARER_TOKEN is required")
	}

	params := map[string]any{"action": action, "path": *remote}
	if *target != "" {
		params["target_id"] = *target
	}
	var expected proto.FileTransferResult
	if action == "upload" {
		data, err := readLocalFile(*local)
		if err != nil {
			return err
		}
		meta, payload, err := proto.EncodeFilePayload(data)
		if err != nil {
			return err
		}
		expected = meta
		params["upload"] = map[string]any{
			"size": meta.Size, "sha256": meta.SHA256, "encoding": meta.Encoding, "wire_size": meta.WireSize,
			"overwrite": *overwrite, "content_base64": base64.StdEncoding.EncodeToString(payload),
		}
	}

	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "revmcp-file", Version: version}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: *endpoint,
		HTTPClient: &http.Client{
			Transport: bearerTransport{token: token},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		MaxRetries:           -1,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		return err
	}
	defer func() { _ = session.Close() }()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "file", Arguments: params})
	if err != nil {
		return err
	}
	if result.IsError {
		if len(result.Content) > 0 {
			if detail, ok := result.Content[0].(*mcp.TextContent); ok {
				return errors.New(detail.Text)
			}
		}
		return errors.New("file transfer failed")
	}
	meta, err := fileTransferMetadata(result)
	if err != nil {
		return err
	}
	if action == "upload" {
		if meta != expected {
			return errors.New("remote upload receipt does not match the local file")
		}
	} else {
		if err := saveDownload(result, meta, *local, *overwrite); err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(meta)
}

func checkFileEndpoint(endpoint, target string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return errors.New("--endpoint must be an HTTP(S) MCP URL without embedded credentials")
	}
	if strings.HasSuffix(u.Path, "/mcp") {
		if target == "" {
			return errors.New("--target is required with the aggregated /mcp endpoint")
		}
	} else if target != "" {
		return errors.New("omit --target when using an isolated /mcp/{target_id} endpoint")
	}
	return nil
}

func readLocalFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > proto.MaxFileTransferBytes {
		return nil, fmt.Errorf("local source must be a regular file of at most %d bytes", proto.MaxFileTransferBytes)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("local source must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, proto.MaxFileTransferBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > proto.MaxFileTransferBytes {
		return nil, fmt.Errorf("local file exceeds %d bytes", proto.MaxFileTransferBytes)
	}
	return data, nil
}

func fileTransferMetadata(result *mcp.CallToolResult) (proto.FileTransferResult, error) {
	var meta proto.FileTransferResult
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		return meta, err
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return meta, err
	}
	if err := meta.Validate(); err != nil {
		return meta, fmt.Errorf("server returned invalid file transfer metadata: %w", err)
	}
	return meta, nil
}

func saveDownload(result *mcp.CallToolResult, meta proto.FileTransferResult, path string, overwrite bool) error {
	if len(result.Content) != 1 {
		return errors.New("server returned invalid file content")
	}
	content, ok := result.Content[0].(*mcp.TextContent)
	if !ok || !strings.HasPrefix(content.Text, "<remote_output ") {
		return errors.New("server returned invalid file content")
	}
	_, body, opened := strings.Cut(content.Text, ">\n")
	encoded, closed := strings.CutSuffix(body, "\n</remote_output>")
	if !opened || !closed {
		return errors.New("server returned invalid file content")
	}
	payload, err := proto.DecodeFileBase64(meta, encoded)
	if err != nil {
		return err
	}
	data, err := proto.DecodeFilePayload(meta, payload)
	if err != nil {
		return err
	}
	return writeLocalDownload(path, data, overwrite)
}

func writeLocalDownload(path string, data []byte, overwrite bool) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || !overwrite {
			return fmt.Errorf("local destination %q already exists", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".revmcp-download-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return err
	}
	if overwrite {
		return os.Rename(f.Name(), path)
	}
	return os.Link(f.Name(), path)
}
