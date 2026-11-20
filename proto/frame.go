package proto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// ProtocolVersion is the southbound RPC protocol version exchanged during registration.
	ProtocolVersion = 1

	// MaxFrameSize caps a single wire frame payload to 2 MiB to prevent unbounded memory allocation.
	MaxFrameSize = 2 * 1024 * 1024

	// DefaultMaxOutputBytes is the default output truncation limit enforced on the agent side.
	DefaultMaxOutputBytes = 32 * 1024

	// HardMaxOutputBytes is the upper bound allowed for tool output caps.
	HardMaxOutputBytes = 128 * 1024

	frameHeaderLen = 4
)

var (
	// ErrFrameTooLarge indicates a frame exceeds MaxFrameSize.
	ErrFrameTooLarge = errors.New("proto: frame exceeds max size")
	// ErrEmptyFrame indicates a zero-length frame header was received.
	ErrEmptyFrame = errors.New("proto: empty frame")
)

// WriteFrame marshals v as JSON and writes a 4-byte big-endian length-prefixed frame to w.
func WriteFrame(w io.Writer, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("proto: marshal frame: %w", err)
	}
	if len(payload) == 0 {
		return ErrEmptyFrame
	}
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, len(payload), MaxFrameSize)
	}

	var header [frameHeaderLen]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("proto: write frame header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("proto: write frame payload: %w", err)
	}
	return nil
}

// ReadFrame reads a single 4-byte big-endian length-prefixed JSON frame from r into dst.
func ReadFrame(r io.Reader, dst any) error {
	var header [frameHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return fmt.Errorf("proto: read frame header: %w", err)
	}

	size := binary.BigEndian.Uint32(header[:])
	if size == 0 {
		return ErrEmptyFrame
	}
	if size > MaxFrameSize {
		return fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, size, MaxFrameSize)
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return fmt.Errorf("proto: read frame payload: %w", err)
	}
	if err := json.Unmarshal(payload, dst); err != nil {
		return fmt.Errorf("proto: unmarshal frame: %w", err)
	}
	return nil
}
