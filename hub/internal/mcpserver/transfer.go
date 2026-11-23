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

type TargetFileInput struct {
	TargetID string `json:"target_id" jsonschema:"Online target agent ID from list_targets"`
	FileInput
}

type FileInput struct {
	Action string         `json:"action" jsonschema:"download or upload"`
	Path   string         `json:"path" jsonschema:"Absolute remote file path"`
	Upload *UploadPayload `json:"upload,omitempty" jsonschema:"File bytes and metadata required for action=upload"`
}

type UploadPayload struct {
	Size          int    `json:"size" jsonschema:"Original file size in bytes from 0 through 10000000"`
	SHA256        string `json:"sha256" jsonschema:"Lowercase SHA-256 hex digest of the original file"`
	Encoding      string `json:"encoding" jsonschema:"File encoding: identity or gzip"`
	WireSize      int    `json:"wire_size" jsonschema:"Number of bytes after encoding and before Base64"`
	Overwrite     bool   `json:"overwrite,omitempty" jsonschema:"Replace an existing regular file (default false)"`
	ContentBase64 string `json:"content_base64" jsonschema:"Standard padded Base64 of the encoded file bytes"`
}

func (g *Gateway) registerTransferTools(srv *mcp.Server, targetID string) {
	tool := &mcp.Tool{
		Name:        "file",
		Description: "Download or upload one regular file up to 10 MB. Download uses read; upload writes to a full Agent and requires exec:full or exec:session. Payloads use identity or gzip encoding.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptrBool(true)},
	}
	if targetID != "" {
		mcp.AddTool(srv, tool, func(ctx context.Context, req *mcp.CallToolRequest, in FileInput) (*mcp.CallToolResult, proto.FileTransferResult, error) {
			return g.handleFile(ctx, req, targetID, in)
		})
		return
	}
	mcp.AddTool(srv, tool, func(ctx context.Context, req *mcp.CallToolRequest, in TargetFileInput) (*mcp.CallToolResult, proto.FileTransferResult, error) {
		return g.handleFile(ctx, req, in.TargetID, in.FileInput)
	})
}

func (g *Gateway) handleFile(ctx context.Context, req *mcp.CallToolRequest, targetID string, in FileInput) (*mcp.CallToolResult, proto.FileTransferResult, error) {
	start := time.Now()
	args := map[string]any{"action": in.Action, "path": in.Path}
	reject := func(err error) (*mcp.CallToolResult, proto.FileTransferResult, error) {
		g.auditCall(newTraceID(), tokenInfo(req), targetID, "file", args, "deny", err.Error(), nil, time.Since(start), false)
		return nil, proto.FileTransferResult{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	switch in.Action {
	case "download":
		if in.Upload != nil {
			return reject(fmt.Errorf("upload parameters are only accepted for action=upload"))
		}
		var result proto.FileDownload
		err := g.callAgent(ctx, req, targetID, "file", policy.ScopeRead, proto.MethodFSDownload,
			proto.FSDownloadRequest{Path: in.Path}, &result, args)
		if err != nil {
			return nil, proto.FileTransferResult{}, err
		}
		return textResult(targetID, 0, false, base64.StdEncoding.EncodeToString(result.Data)), result.FileTransferResult, nil

	case "upload":
		if in.Upload == nil {
			return reject(fmt.Errorf("upload parameters are required for action=upload"))
		}
		info := tokenInfo(req)
		if err := policy.Authorize(info, "", targetID); err != nil {
			return reject(err)
		}
		if !policy.HasScope(info.Scopes, policy.ScopeExecFull) && !policy.HasScope(info.Scopes, policy.ScopeExecSession) {
			return reject(fmt.Errorf("file upload requires exec:full or exec:session"))
		}
		upload := in.Upload
		args["size"] = upload.Size
		args["encoding"] = upload.Encoding
		args["wire_size"] = upload.WireSize
		args["overwrite"] = upload.Overwrite
		meta := proto.FileTransferResult{Size: upload.Size, SHA256: upload.SHA256, Encoding: upload.Encoding, WireSize: upload.WireSize}
		data, err := proto.DecodeFileBase64(meta, upload.ContentBase64)
		if err != nil {
			return reject(err)
		}
		if _, err := proto.DecodeFilePayload(meta, data); err != nil {
			return reject(err)
		}
		params := proto.FileUpload{
			FSUploadRequest: proto.FSUploadRequest{Path: in.Path, FileTransferResult: meta, Overwrite: upload.Overwrite},
			Data:            data,
		}
		var result proto.FileTransferResult
		err = g.callAgent(ctx, req, targetID, "file", "", proto.MethodFSUpload, params, &result, args)
		if err != nil {
			return nil, proto.FileTransferResult{}, err
		}
		return textResult(targetID, 0, false, mustPrettyJSON(result)), result, nil

	default:
		return reject(fmt.Errorf("file action must be download or upload"))
	}
}

func checkTransferAgent(method string, info proto.AgentInfo) error {
	switch method {
	case proto.MethodFSUpload:
		if !info.Mode.Allows(proto.ModeFull) {
			return fmt.Errorf("file upload requires full Agent mode")
		}
	case proto.MethodFSDownload:
		if !info.Mode.Allows(proto.ModeReadOnly) {
			return fmt.Errorf("file download requires readonly Agent mode or higher")
		}
	default:
		return nil
	}
	if info.FileTransferVersion != proto.FileTransferVersion {
		return fmt.Errorf("target %q needs an Agent with file transfer protocol version %d", info.TargetID, proto.FileTransferVersion)
	}
	return nil
}
