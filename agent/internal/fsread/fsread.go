package fsread

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

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
	// ErrPathDenied indicates the path was blocked by agent allow/deny path policy.
	ErrPathDenied = errors.New("fsread: path denied by policy")
)

// DefaultDenyPaths protects high-value host credential files even in readonly mode.
var DefaultDenyPaths = []string{
	"/etc/shadow",
	"/etc/shadow-",
	"/etc/gshadow",
	"/etc/gshadow-",
	"/proc/*/environ",
	"/proc/*/mem",
	"/proc/kcore",
	"/root/.ssh/*",
	"/home/*/.ssh/*",
	"/etc/kubernetes/pki/*",
}

// Policy controls which filesystem paths the agent permits for fs.read and fs.grep.
type Policy struct {
	AllowPaths    []string
	DenyPaths     []string
	NoDefaultDeny bool
}

// DefaultPolicy returns a Policy enforcing DefaultDenyPaths.
func DefaultPolicy() Policy {
	return Policy{}
}

// Reader performs policy-checked, bounded file reads and regex grep operations.
type Reader struct {
	allowPatterns []string
	denyPatterns  []string
}

// NewReader constructs a Reader enforcing p (combining DefaultDenyPaths unless NoDefaultDeny is true).
func NewReader(p Policy) *Reader {
	var denies []string
	if !p.NoDefaultDeny {
		denies = append(denies, DefaultDenyPaths...)
	}
	for _, pat := range p.DenyPaths {
		if trimmed := strings.TrimSpace(pat); trimmed != "" {
			denies = append(denies, filepath.Clean(trimmed))
		}
	}

	var allows []string
	for _, pat := range p.AllowPaths {
		if trimmed := strings.TrimSpace(pat); trimmed != "" {
			allows = append(allows, filepath.Clean(trimmed))
		}
	}

	return &Reader{
		allowPatterns: allows,
		denyPatterns:  denies,
	}
}

// Read is a convenience wrapper using DefaultPolicy.
func Read(req proto.FSReadRequest) (*proto.FSReadResult, error) {
	return NewReader(DefaultPolicy()).Read(req)
}

// Grep is a convenience wrapper using DefaultPolicy.
func Grep(req proto.FSGrepRequest) (*proto.FSGrepResult, error) {
	return NewReader(DefaultPolicy()).Grep(req)
}

func clampMaxBytes(v int) int {
	if v <= 0 {
		return proto.DefaultMaxOutputBytes
	}
	if v > proto.HardMaxOutputBytes {
		return proto.HardMaxOutputBytes
	}
	return v
}

func (r *Reader) checkPathPolicy(cleanedPath string) error {
	candidates := []string{cleanedPath}
	if resolved, err := filepath.EvalSymlinks(cleanedPath); err == nil && resolved != "" && resolved != cleanedPath {
		candidates = append(candidates, filepath.Clean(resolved))
	}

	for _, c := range candidates {
		for _, deny := range r.denyPatterns {
			if matchPathPattern(deny, c) {
				return fmt.Errorf("%w: %q matches deny rule %q", ErrPathDenied, cleanedPath, deny)
			}
		}
	}

	if len(r.allowPatterns) > 0 {
		// Check the canonical resolved path (last candidate) against allowPatterns.
		target := candidates[len(candidates)-1]
		allowed := false
		for _, allow := range r.allowPatterns {
			if matchPathPattern(allow, target) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: %q is outside configured --allow-path rules", ErrPathDenied, cleanedPath)
		}
	}

	return nil
}

func matchPathPattern(pattern, candidate string) bool {
	if pattern == candidate {
		return true
	}
	if matched, err := path.Match(pattern, candidate); err == nil && matched {
		return true
	}
	// Support recursive prefix rules when pattern ends with "/*" (e.g. "/var/log/*") or is a directory prefix.
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*")
		if strings.HasPrefix(candidate, prefix) {
			return true
		}
		// Handle wildcard intermediate directories such as "/home/*/.ssh/*".
		dirPat := strings.TrimSuffix(pattern, "/*")
		for cur := path.Dir(candidate); cur != "/" && cur != "."; cur = path.Dir(cur) {
			if matched, err := path.Match(dirPat, cur); err == nil && matched {
				return true
			}
		}
	}
	if strings.HasPrefix(candidate, pattern+"/") {
		return true
	}
	return false
}

func (r *Reader) openSafeFile(rawPath string) (*os.File, os.FileInfo, error) {
	if strings.TrimSpace(rawPath) == "" {
		return nil, nil, fmt.Errorf("%w: empty path", ErrInvalidPath)
	}
	cleaned := filepath.Clean(rawPath)
	if err := r.checkPathPolicy(cleaned); err != nil {
		return nil, nil, err
	}

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

// Read returns a bounded chunk (when Offset is set) or tail (by tail_lines) of a file.
func (r *Reader) Read(req proto.FSReadRequest) (*proto.FSReadResult, error) {
	f, fi, err := r.openSafeFile(req.Path)
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

func readTail(f *os.File, filePath string, size int64, tailLines, maxBytes int) (*proto.FSReadResult, error) {
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
		Path:       filePath,
		Content:    string(content),
		Offset:     actualOffset,
		BytesRead:  len(content),
		FileSize:   size,
		Truncated:  actualOffset > 0,
		NextOffset: actualOffset + int64(len(content)),
	}, nil
}

// Grep streams a file line-by-line and returns bounded regex matches.
func (r *Reader) Grep(req proto.FSGrepRequest) (*proto.FSGrepResult, error) {
	if req.Pattern == "" {
		return nil, fmt.Errorf("%w: empty pattern", ErrInvalidPath)
	}
	re, err := regexp.Compile(req.Pattern)
	if err != nil {
		return nil, fmt.Errorf("fsread: compile regex: %w", err)
	}

	f, _, err := r.openSafeFile(req.Path)
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
