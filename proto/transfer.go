package proto

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

const (
	MaxFileTransferBytes = 10_000_000
	FileTransferVersion  = 2
	FileEncodingIdentity = "identity"
	FileEncodingGzip     = "gzip"
	MethodFSUpload       = "fs.upload"
	MethodFSDownload     = "fs.download"
)

type FSUploadRequest struct {
	Path string `json:"path"`
	FileTransferResult
	Overwrite bool `json:"overwrite,omitempty"`
}

type FSDownloadRequest struct {
	Path string `json:"path"`
}

type FileTransferResult struct {
	Size     int    `json:"size"`
	SHA256   string `json:"sha256"`
	Encoding string `json:"encoding"`
	WireSize int    `json:"wire_size"`
}

// FileUpload and FileDownload carry the encoded bytes alongside the framed RPC metadata.
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

// EncodeFilePayload uses gzip only when it saves bytes.
func EncodeFilePayload(data []byte) (FileTransferResult, []byte, error) {
	if len(data) > MaxFileTransferBytes {
		return FileTransferResult{}, nil, fmt.Errorf("file exceeds %d bytes", MaxFileTransferBytes)
	}
	meta := FileTransferResult{Size: len(data), SHA256: FileSHA256(data), Encoding: FileEncodingIdentity, WireSize: len(data)}
	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
	if err != nil {
		return FileTransferResult{}, nil, err
	}
	if _, err := writer.Write(data); err != nil {
		return FileTransferResult{}, nil, err
	}
	if err := writer.Close(); err != nil {
		return FileTransferResult{}, nil, err
	}
	if compressed.Len() < len(data) {
		meta.Encoding = FileEncodingGzip
		meta.WireSize = compressed.Len()
		return meta, compressed.Bytes(), nil
	}
	return meta, data, nil
}

// Validate checks bounds and encoding before any payload allocation.
func (m FileTransferResult) Validate() error {
	if m.Size < 0 || m.Size > MaxFileTransferBytes || m.WireSize < 0 || m.WireSize > MaxFileTransferBytes {
		return fmt.Errorf("file and wire sizes must be between 0 and %d bytes", MaxFileTransferBytes)
	}
	digest, err := hex.DecodeString(m.SHA256)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != m.SHA256 {
		return fmt.Errorf("file SHA-256 must be a lowercase hexadecimal digest")
	}
	switch m.Encoding {
	case FileEncodingIdentity:
		if m.Size == m.WireSize {
			return nil
		}
	case FileEncodingGzip:
		if m.WireSize > 0 && m.WireSize < m.Size {
			return nil
		}
	}
	return fmt.Errorf("invalid file encoding or wire size")
}

func DecodeFileBase64(meta FileTransferResult, encoded string) ([]byte, error) {
	if err := meta.Validate(); err != nil {
		return nil, err
	}
	if len(encoded) != base64.StdEncoding.EncodedLen(meta.WireSize) {
		return nil, fmt.Errorf("Base64 length does not match file wire size")
	}
	return base64.StdEncoding.Strict().DecodeString(encoded)
}

// DecodeFilePayload verifies the original size and digest before returning bytes.
func DecodeFilePayload(meta FileTransferResult, payload []byte) ([]byte, error) {
	if err := meta.Validate(); err != nil {
		return nil, err
	}
	if len(payload) != meta.WireSize {
		return nil, fmt.Errorf("file wire size does not match the payload")
	}
	data := payload
	if meta.Encoding == FileEncodingGzip {
		source := bytes.NewReader(payload)
		reader, err := gzip.NewReader(source)
		if err != nil {
			return nil, fmt.Errorf("open gzip file payload: %w", err)
		}
		defer func() { _ = reader.Close() }()
		reader.Multistream(false)
		data, err = io.ReadAll(io.LimitReader(reader, int64(meta.Size)+1))
		if err != nil {
			return nil, fmt.Errorf("decompress file payload: %w", err)
		}
		if source.Len() != 0 {
			return nil, fmt.Errorf("gzip file payload contains trailing data")
		}
	}
	if len(data) != meta.Size {
		return nil, fmt.Errorf("original file size does not match the payload")
	}
	if FileSHA256(data) != meta.SHA256 {
		return nil, fmt.Errorf("file SHA-256 does not match the payload")
	}
	return data, nil
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
