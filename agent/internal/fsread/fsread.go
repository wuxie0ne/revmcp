package fsread

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/revmcp/revmcp/proto"
)

const (
	defaultTailLines  = 200
	defaultMaxMatches = 100
	hardMaxMatches    = 500
	maxScanLineBytes  = 64 * 1024
)

var (
	// ErrInvalidPath indicates a missing or unsupported path (e.g., directory, FIFO, or device file).
	ErrInvalidPath = errors.New("fsread: invalid or unsupported file path")
)

func clampMaxBytes(v int) int {
	if v <= 0 {
		return proto.DefaultMaxOutputBytes
	}
	if v > proto.HardMaxOutputBytes {
		return proto.HardMaxOutputBytes
	}
	return v
}

func openSafeFile(rawPath string) (*os.File, os.FileInfo, error) {
	if rawPath == "" {
		return nil, nil, fmt.Errorf("%w: empty path", ErrInvalidPath)
	}
	cleaned := filepath.Clean(rawPath)
	fi, err := os.Stat(cleaned)
	if err != nil {
		return nil, nil, err
	}
	if fi.IsDir() {
		return nil, nil, fmt.Errorf("%w: path is a directory", ErrInvalidPath)
	}
	mode := fi.Mode()
	// Reject FIFOs, sockets, char/block devices so reads cannot hang on /dev/zero or named pipes.
	if mode&(os.ModeNamedPipe|os.ModeSocket|os.ModeDevice|os.ModeCharDevice) != 0 {
		return nil, nil, fmt.Errorf("%w: special device or pipe is not readable", ErrInvalidPath)
	}
	f, err := os.Open(cleaned)
	if err != nil {
		return nil, nil, err
	}
	return f, fi, nil
}

// Read returns a bounded chunk (by offset) or tail (by tail_lines) of a file.
func Read(req proto.FSReadRequest) (*proto.FSReadResult, error) {
	f, fi, err := openSafeFile(req.Path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	maxBytes := clampMaxBytes(req.MaxBytes)
	size := fi.Size()

	// Tail mode when TailLines > 0, or when Offset is omitted on a file larger than maxBytes.
	if req.TailLines > 0 || (req.Offset == nil && size > int64(maxBytes)) {
		tailLines := req.TailLines
		if tailLines <= 0 {
			tailLines = defaultTailLines
		}
		return readTail(f, req.Path, size, tailLines, maxBytes)
	}

	var offset int64
	if req.Offset != nil && *req.Offset > 0 {
		offset = *req.Offset
	}
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, fmt.Errorf("fsread: seek %d: %w", offset, err)
		}
	}

	// Read at most maxBytes+1 so we know whether additional content remains.
	buf := make([]byte, maxBytes+1)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("fsread: read: %w", err)
	}

	truncated := n > maxBytes
	if truncated {
		n = maxBytes
	}

	return &proto.FSReadResult{
		Path:       req.Path,
		Content:    string(buf[:n]),
		Offset:     offset,
		BytesRead:  n,
		FileSize:   size,
		Truncated:  truncated,
		NextOffset: offset + int64(n),
	}, nil
}

func readTail(f *os.File, path string, size int64, tailLines, maxBytes int) (*proto.FSReadResult, error) {
	start := size - int64(maxBytes)
	if start < 0 {
		start = 0
	}
	if start > 0 {
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			return nil, fmt.Errorf("fsread: seek tail: %w", err)
		}
	}

	buf := make([]byte, maxBytes)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("fsread: read tail: %w", err)
	}
	data := buf[:n]

	// Trim to last tailLines lines.
	linesFound := 0
	cutIdx := 0
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == '\n' {
			if i == len(data)-1 {
				continue
			}
			linesFound++
			if linesFound == tailLines {
				cutIdx = i + 1
				break
			}
		}
	}

	content := data[cutIdx:]
	actualOffset := start + int64(cutIdx)
	return &proto.FSReadResult{
		Path:       path,
		Content:    string(content),
		Offset:     actualOffset,
		BytesRead:  len(content),
		FileSize:   size,
		Truncated:  actualOffset > 0,
		NextOffset: actualOffset + int64(len(content)),
	}, nil
}

// Grep streams a file line-by-line and returns bounded regex matches.
func Grep(req proto.FSGrepRequest) (*proto.FSGrepResult, error) {
	if req.Pattern == "" {
		return nil, fmt.Errorf("%w: empty pattern", ErrInvalidPath)
	}
	re, err := regexp.Compile(req.Pattern)
	if err != nil {
		return nil, fmt.Errorf("fsread: compile regex: %w", err)
	}

	f, _, err := openSafeFile(req.Path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	maxMatches := req.MaxMatches
	if maxMatches <= 0 {
		maxMatches = defaultMaxMatches
	}
	if maxMatches > hardMaxMatches {
		maxMatches = hardMaxMatches
	}
	maxBytes := clampMaxBytes(req.MaxBytes)

	reader := bufio.NewReaderSize(f, 32*1024)
	var matches []proto.GrepMatch
	totalBytes := 0
	lineNum := 0
	truncated := false

	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			lineNum++
			if len(line) > maxScanLineBytes {
				line = line[:maxScanLineBytes]
			}
			line = bytes.TrimRight(line, "\r\n")
			if re.Match(line) {
				if len(matches) >= maxMatches || totalBytes+len(line) > maxBytes {
					truncated = true
					break
				}
				totalBytes += len(line)
				matches = append(matches, proto.GrepMatch{
					LineNumber: lineNum,
					Line:       string(line),
				})
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("fsread: scan line %d: %w", lineNum, readErr)
		}
	}

	return &proto.FSGrepResult{
		Path:      req.Path,
		Matches:   matches,
		Truncated: truncated,
	}, nil
}
