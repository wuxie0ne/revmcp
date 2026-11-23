package mcpserver

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/revmcp/revmcp/hub/internal/policy"
	"github.com/revmcp/revmcp/proto"
)

type DownloadFileInput struct {
	TargetID string `json:"target_id" jsonschema:"Online target agent ID from list_targets"`
	DownloadPath
}

type DownloadPath struct {
	Path string `json:"path" jsonschema:"Absolute path of the regular file to download"`
}

type UploadFileInput struct {
	TargetID string `json:"target_id" jsonschema:"Online target agent ID from list_targets"`
	UploadPayload
}

type UploadPayload struct {
	Path          string `json:"path" jsonschema:"Absolute destination path under an Agent upload directory"`
	Size          int    `json:"size" jsonschema:"Unencoded file size in bytes from 0 through 10000000"`
	SHA256        string `json:"sha256" jsonschema:"Lowercase SHA-256 hex digest of the unencoded file"`
	Overwrite     bool   `json:"overwrite,omitempty" jsonschema:"Replace an existing regular file (default false)"`
	ContentBase64 string `json:"content_base64" jsonschema:"Standard padded Base64 file bytes"`
}

func (g *Gateway) registerTransferTools(srv *mcp.Server, targetID string) {
	download := &mcp.Tool{
		Name:        "download_file",
		Description: "Download one regular file up to 10 MB. Returns Base64 inside remote_output and structured size and SHA-256.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, DestructiveHint: ptrBool(false)},
	}
	upload := &mcp.Tool{
		Name:        "upload_file",
		Description: "Write one file up to 10 MB in an enabled upload directory. Requires file:upload and full Agent mode. Does not run commands.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptrBool(true)},
	}
	if targetID != "" {
		mcp.AddTool(srv, download, func(ctx context.Context, req *mcp.CallToolRequest, in DownloadPath) (*mcp.CallToolResult, proto.FileTransferResult, error) {
			return g.downloadFile(ctx, req, targetID, in.Path)
		})
		mcp.AddTool(srv, upload, func(ctx context.Context, req *mcp.CallToolRequest, in UploadPayload) (*mcp.CallToolResult, proto.FileTransferResult, error) {
			return g.uploadFile(ctx, req, targetID, in)
		})
		return
	}
	mcp.AddTool(srv, download, func(ctx context.Context, req *mcp.CallToolRequest, in DownloadFileInput) (*mcp.CallToolResult, proto.FileTransferResult, error) {
		return g.downloadFile(ctx, req, in.TargetID, in.Path)
	})
	mcp.AddTool(srv, upload, func(ctx context.Context, req *mcp.CallToolRequest, in UploadFileInput) (*mcp.CallToolResult, proto.FileTransferResult, error) {
		return g.uploadFile(ctx, req, in.TargetID, in.UploadPayload)
	})
}

func (g *Gateway) downloadFile(ctx context.Context, req *mcp.CallToolRequest, targetID, path string) (*mcp.CallToolResult, proto.FileTransferResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var result proto.FileDownload
	err := g.callAgent(ctx, req, targetID, "download_file", policy.ScopeRead, proto.MethodFSDownload,
		proto.FSDownloadRequest{Path: path}, &result, map[string]any{"path": path})
	if err != nil {
		return nil, proto.FileTransferResult{}, err
	}
	return textResult(targetID, 0, false, base64.StdEncoding.EncodeToString(result.Data)), result.FileTransferResult, nil
}

func (g *Gateway) uploadFile(ctx context.Context, req *mcp.CallToolRequest, targetID string, in UploadPayload) (*mcp.CallToolResult, proto.FileTransferResult, error) {
	start := time.Now()
	args := map[string]any{"path": in.Path, "size": in.Size, "overwrite": in.Overwrite}
	if err := policy.Authorize(tokenInfo(req), policy.ScopeFileUpload, targetID); err != nil {
		g.auditCall(newTraceID(), tokenInfo(req), targetID, "upload_file", args, "deny", err.Error(), nil, time.Since(start), false)
		return nil, proto.FileTransferResult{}, err
	}
	data, err := decodeUpload(in)
	if err != nil {
		g.auditCall(newTraceID(), tokenInfo(req), targetID, "upload_file", args, "deny", err.Error(), nil, time.Since(start), false)
		return nil, proto.FileTransferResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var result proto.FileTransferResult
	params := proto.FileUpload{
		FSUploadRequest: proto.FSUploadRequest{Path: in.Path, Size: in.Size, SHA256: in.SHA256, Overwrite: in.Overwrite},
		Data:            data,
	}
	err = g.callAgent(ctx, req, targetID, "upload_file", policy.ScopeFileUpload, proto.MethodFSUpload, params, &result, args)
	if err != nil {
		return nil, proto.FileTransferResult{}, err
	}
	return textResult(targetID, 0, false, mustPrettyJSON(result)), result, nil
}

func decodeUpload(in UploadPayload) ([]byte, error) {
	if in.Size < 0 || in.Size > proto.MaxFileTransferBytes ||
		len(in.ContentBase64) != base64.StdEncoding.EncodedLen(in.Size) {
		return nil, fmt.Errorf("file size must match the payload and be between 0 and %d bytes", proto.MaxFileTransferBytes)
	}
	data, err := base64.StdEncoding.Strict().DecodeString(in.ContentBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid Base64 file payload: %w", err)
	}
	if err := proto.ValidateFilePayload(in.Size, in.SHA256, data); err != nil {
		return nil, err
	}
	return data, nil
}

func checkTransferAgent(method string, info proto.AgentInfo) error {
	switch method {
	case proto.MethodFSUpload:
		if !info.Mode.Allows(proto.ModeFull) {
			return fmt.Errorf("upload_file requires full Agent mode")
		}
	case proto.MethodFSDownload:
		if !info.Mode.Allows(proto.ModeReadOnly) {
			return fmt.Errorf("download_file requires readonly Agent mode or higher")
		}
	default:
		return nil
	}
	if !info.FileTransfer {
		return fmt.Errorf("target %q needs an Agent version with file transfer support", info.TargetID)
	}
	return nil
}
