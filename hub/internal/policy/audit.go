package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// AuditEntry represents one structured JSONL audit log line emitted for every tools/call.
type AuditEntry struct {
	Timestamp    time.Time      `json:"ts"`
	TraceID      string         `json:"trace_id"`
	User         string         `json:"user"`
	TargetID     string         `json:"target_id,omitempty"`
	Tool         string         `json:"tool"`
	ArgsRedacted map[string]any `json:"args_redacted,omitempty"`
	Decision     string         `json:"decision"` // "allow" | "deny"
	Reason       string         `json:"reason,omitempty"`
	ExitCode     *int           `json:"exit_code,omitempty"`
	DurationMS   int64          `json:"duration_ms"`
	Truncated    bool           `json:"truncated,omitempty"`
}

// AuditLogger writes thread-safe JSONL audit records.
type AuditLogger struct {
	mu     sync.Mutex
	w      io.Writer
	closer io.Closer
}

// NewAuditLogger opens a JSONL audit sink (file path or "-" for os.Stderr).
func NewAuditLogger(path string) (*AuditLogger, error) {
	if path == "" || path == "-" {
		return &AuditLogger{w: os.Stderr}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("audit: create parent dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %q: %w", path, err)
	}
	return &AuditLogger{w: f, closer: f}, nil
}

// NewAuditLoggerWithWriter creates an AuditLogger writing to an arbitrary io.Writer (useful for tests).
func NewAuditLoggerWithWriter(w io.Writer) *AuditLogger {
	return &AuditLogger{w: w}
}

// Log writes a single redacted JSONL audit entry.
func (a *AuditLogger) Log(entry AuditEntry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	if entry.ArgsRedacted != nil {
		entry.ArgsRedacted = RedactMap(entry.ArgsRedacted)
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()
	_, err = a.w.Write(line)
	return err
}

// Close closes the underlying audit file if owned by the logger.
func (a *AuditLogger) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closer != nil {
		return a.closer.Close()
	}
	return nil
}

// RedactMap masks sensitive argument keys before writing to audit logs.
func RedactMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "token") ||
			strings.Contains(lower, "secret") ||
			strings.Contains(lower, "password") ||
			strings.Contains(lower, "authorization") ||
			strings.Contains(lower, "apikey") ||
			strings.Contains(lower, "api_key") {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = v
	}
	return out
}
