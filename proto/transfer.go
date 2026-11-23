package proto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

const (
	MaxFileTransferBytes = 10_000_000
	MethodFSUpload       = "fs.upload"
	MethodFSDownload     = "fs.download"
)

type FSUploadRequest struct {
	Path      string `json:"path"`
	Size      int    `json:"size"`
	SHA256    string `json:"sha256"`
	Overwrite bool   `json:"overwrite,omitempty"`
}

type FSDownloadRequest struct {
	Path string `json:"path"`
}

type FileTransferResult struct {
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

// FileUpload and FileDownload carry the raw bytes alongside the framed RPC metadata.
type FileUpload struct {
	FSUploadRequest
	Data []byte `json:"-"`
}

type FileDownload struct {
	FileTransferResult
	Data []byte `json:"-"`
}

func FileSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func ValidateFilePayload(size int, digest string, data []byte) error {
	if size < 0 || size > MaxFileTransferBytes || len(data) != size {
		return fmt.Errorf("file size must match the payload and be between 0 and %d bytes", MaxFileTransferBytes)
	}
	if FileSHA256(data) != digest {
		return fmt.Errorf("file SHA-256 does not match the payload")
	}
	return nil
}

// ReadFilePayload reads the exact byte count declared in the transfer frame.
func ReadFilePayload(r io.Reader, size int) ([]byte, error) {
	if size < 0 || size > MaxFileTransferBytes {
		return nil, fmt.Errorf("file size must be between 0 and %d bytes", MaxFileTransferBytes)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("read file payload: %w", err)
	}
	return data, nil
}

// WriteFilePayload bounds each write well below the WebSocket message limit.
func WriteFilePayload(w io.Writer, data []byte) error {
	if len(data) > MaxFileTransferBytes {
		return fmt.Errorf("file exceeds %d bytes", MaxFileTransferBytes)
	}
	const chunkSize = 256 * 1024
	for len(data) > 0 {
		chunk := data[:min(len(data), chunkSize)]
		n, err := w.Write(chunk)
		if err != nil {
			return fmt.Errorf("write file payload: %w", err)
		}
		if n != len(chunk) {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
