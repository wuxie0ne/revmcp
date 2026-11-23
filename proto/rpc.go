package proto

import (
	"encoding/json"
	"fmt"
	"time"
)

// Mode represents the agent-side hard permission boundary set at startup.
type Mode string

const (
	ModeReadOnly   Mode = "readonly"
	ModeRestricted Mode = "restricted"
	ModeFull       Mode = "full"
)

// ParseMode parses and validates an agent execution mode, failing closed on unknown values.
func ParseMode(raw string) (Mode, error) {
	switch Mode(raw) {
	case ModeReadOnly:
		return ModeReadOnly, nil
	case ModeRestricted:
		return ModeRestricted, nil
	case ModeFull:
		return ModeFull, nil
	default:
		return "", fmt.Errorf("proto: unrecognized mode %q", raw)
	}
}

// Level returns the numeric privilege rank of a valid Mode (higher is more permissive).
func (m Mode) Level() int {
	switch m {
	case ModeReadOnly:
		return 1
	case ModeRestricted:
		return 2
	case ModeFull:
		return 3
	default:
		return 0
	}
}

// Allows returns true if mode m is at least as permissive as required.
func (m Mode) Allows(required Mode) bool {
	return m.Level() > 0 && required.Level() > 0 && m.Level() >= required.Level()
}

// RPC method names shared between Hub and Agent.
const (
	MethodAgentRegister = "agent.register"
	MethodAgentPing     = "agent.ping"
	MethodAgentShutdown = "agent.shutdown"
	MethodSysInfo       = "sys.info"
	MethodProcList      = "proc.list"
	MethodNetSockets    = "net.sockets"
	MethodFSRead        = "fs.read"
	MethodFSGrep        = "fs.grep"
	MethodCmdExec       = "cmd.exec"
	MethodSessionOpen   = "session.open"
	MethodSessionExec   = "session.exec"
	MethodSessionClose  = "session.close"
)

// Structured RPC error codes for deterministic Hub-to-MCP mapping.
const (
	ErrCodeInvalidArgument = "INVALID_ARGUMENT"
	ErrCodeModeDenied      = "MODE_DENIED"
	ErrCodePolicyDenied    = "POLICY_DENIED"
	ErrCodeNotFound        = "NOT_FOUND"
	ErrCodeTimeout         = "TIMEOUT"
	ErrCodeCancelled       = "CANCELLED"
	ErrCodeUnsupported     = "UNSUPPORTED"
	ErrCodeInternal        = "INTERNAL"
)

// Request is the envelope sent over a yamux stream for a single RPC invocation.
type Request struct {
	ID      string          `json:"id"`
	TraceID string          `json:"trace_id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	Data    []byte          `json:"-"`
}

// Response is the envelope returned over the same yamux stream.
type Response struct {
	ID     string          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *RPCError       `json:"error,omitempty"`
}

// RPCError carries a machine-readable error code and human-readable message.
type RPCError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable,omitempty"`
}

func (e *RPCError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// AgentInfo describes a connected target host or container.
type AgentInfo struct {
	TargetID     string            `json:"target_id"`
	Hostname     string            `json:"hostname"`
	OS           string            `json:"os"`
	Kernel       string            `json:"kernel"`
	Arch         string            `json:"arch"`
	InContainer  bool              `json:"in_container"`
	Mode         Mode              `json:"mode"`
	Version      string            `json:"version"`
	Tags         map[string]string `json:"tags,omitempty"`
	StartedAt    time.Time         `json:"started_at"`
	FileTransfer bool              `json:"file_transfer,omitempty"`
}

// RegisterRequest is sent on the initial agent->hub stream after WebSocket upgrade.
type RegisterRequest struct {
	ProtoVersion int       `json:"proto_version"`
	Agent        AgentInfo `json:"agent"`
}

// RegisterResponse acknowledges registration on the initial stream.
type RegisterResponse struct {
	Accepted   bool   `json:"accepted"`
	HubVersion string `json:"hub_version,omitempty"`
	Message    string `json:"message,omitempty"`
}

// PingResult is returned by agent.ping.
type PingResult struct {
	Timestamp     time.Time `json:"timestamp"`
	UptimeSeconds int64     `json:"uptime_seconds"`
	ActiveRPCs    int       `json:"active_rpcs"`
}

// ShutdownRequest asks the agent to disconnect and exit cleanly.
type ShutdownRequest struct {
	Reason       string `json:"reason,omitempty"`
	SelfDestruct bool   `json:"self_destruct,omitempty"`
}

// ShutdownResult confirms receipt of a shutdown directive.
type ShutdownResult struct {
	Accepted bool `json:"accepted"`
}

// SysInfoResult holds pure-Go /proc diagnostic data.
type SysInfoResult struct {
	Hostname      string      `json:"hostname"`
	Kernel        string      `json:"kernel"`
	Arch          string      `json:"arch"`
	InContainer   bool        `json:"in_container"`
	UptimeSeconds float64     `json:"uptime_seconds"`
	LoadAvg       [3]float64  `json:"load_avg"`
	CPUCores      int         `json:"cpu_cores"`
	MemTotalBytes uint64      `json:"mem_total_bytes"`
	MemAvailBytes uint64      `json:"mem_avail_bytes"`
	Mounts        []MountInfo `json:"mounts,omitempty"`
}

// MountInfo describes a mounted filesystem summary.
type MountInfo struct {
	MountPoint string `json:"mount_point"`
	FSType     string `json:"fs_type"`
	TotalBytes uint64 `json:"total_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
}

// ProcListRequest queries /proc/[pid] entries.
type ProcListRequest struct {
	Filter string `json:"filter,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

// ProcessInfo represents one process read from /proc.
type ProcessInfo struct {
	PID      int    `json:"pid"`
	PPID     int    `json:"ppid"`
	State    string `json:"state"`
	UID      int    `json:"uid"`
	RSSBytes uint64 `json:"rss_bytes"`
	Name     string `json:"name"`
	Cmdline  string `json:"cmdline"`
}

// ProcListResult returns matching processes and truncation info.
type ProcListResult struct {
	Total     int           `json:"total"`
	Truncated bool          `json:"truncated"`
	Processes []ProcessInfo `json:"processes"`
}

// SocketInfo represents a listening or active socket parsed from /proc/net.
type SocketInfo struct {
	Proto      string `json:"proto"`
	LocalAddr  string `json:"local_addr"`
	LocalPort  uint16 `json:"local_port"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	RemotePort uint16 `json:"remote_port,omitempty"`
	State      string `json:"state"`
	Inode      uint64 `json:"inode,omitempty"`
}

// NetSocketsResult returns listening sockets and TCP state counts.
type NetSocketsResult struct {
	Listening   []SocketInfo   `json:"listening"`
	StateCounts map[string]int `json:"state_counts,omitempty"`
}

// FSReadRequest reads a bounded chunk (when Offset is set) or tail of a file.
type FSReadRequest struct {
	Path      string `json:"path"`
	Offset    *int64 `json:"offset,omitempty"`
	TailLines int    `json:"tail_lines,omitempty"`
	MaxBytes  int    `json:"max_bytes,omitempty"`
}

// FSReadResult returns bounded file content with metadata.
type FSReadResult struct {
	Path       string `json:"path"`
	Content    string `json:"content"`
	Offset     int64  `json:"offset"`
	BytesRead  int    `json:"bytes_read"`
	FileSize   int64  `json:"file_size"`
	Truncated  bool   `json:"truncated"`
	NextOffset int64  `json:"next_offset"`
}

// FSGrepRequest searches a file line-by-line using a regex pattern.
type FSGrepRequest struct {
	Path       string `json:"path"`
	Pattern    string `json:"pattern"`
	MaxMatches int    `json:"max_matches,omitempty"`
	MaxBytes   int    `json:"max_bytes,omitempty"`
}

// GrepMatch represents a matched line from fs.grep.
type GrepMatch struct {
	LineNumber int    `json:"line_number"`
	Line       string `json:"line"`
}

// FSGrepResult returns bounded regex matches.
type FSGrepResult struct {
	Path      string      `json:"path"`
	Matches   []GrepMatch `json:"matches"`
	Truncated bool        `json:"truncated"`
}

// CmdExecRequest executes a single non-interactive command.
type CmdExecRequest struct {
	Command    string `json:"command"`
	Workdir    string `json:"workdir,omitempty"`
	TimeoutSec int    `json:"timeout_sec,omitempty"`
	MaxBytes   int    `json:"max_bytes,omitempty"`
}

// CmdExecResult holds bounded command output and execution metadata.
type CmdExecResult struct {
	ExitCode   int    `json:"exit_code"`
	Output     string `json:"output"`
	Truncated  bool   `json:"truncated"`
	Dropped    int64  `json:"dropped_bytes,omitempty"`
	TimedOut   bool   `json:"timed_out,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

// SessionOpenRequest opens a persistent shell session (full mode only).
type SessionOpenRequest struct {
	Workdir string `json:"workdir,omitempty"`
}

// SessionOpenResult returns the created session ID.
type SessionOpenResult struct {
	SessionID string `json:"session_id"`
}

// SessionExecRequest executes a command inside an existing shell session.
type SessionExecRequest struct {
	SessionID  string `json:"session_id"`
	Command    string `json:"command"`
	TimeoutSec int    `json:"timeout_sec,omitempty"`
	MaxBytes   int    `json:"max_bytes,omitempty"`
}

// SessionCloseRequest closes an existing shell session.
type SessionCloseRequest struct {
	SessionID string `json:"session_id"`
}

// SessionCloseResult confirms session closure.
type SessionCloseResult struct {
	Closed bool `json:"closed"`
}
