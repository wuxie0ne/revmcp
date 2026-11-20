package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/revmcp/revmcp/agent/internal/executor"
	"github.com/revmcp/revmcp/agent/internal/fsread"
	"github.com/revmcp/revmcp/agent/internal/guard"
	"github.com/revmcp/revmcp/agent/internal/sysinfo"
	"github.com/revmcp/revmcp/agent/internal/tunnel"
	"github.com/revmcp/revmcp/proto"
)

var version = "dev"

type tagFlags map[string]string

func (t tagFlags) String() string { return fmt.Sprintf("%v", map[string]string(t)) }

func (t tagFlags) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok || strings.TrimSpace(k) == "" {
		return fmt.Errorf("invalid tag %q, expected key=value", v)
	}
	t[strings.TrimSpace(k)] = strings.TrimSpace(val)
	return nil
}

type listFlags []string

func (l *listFlags) String() string { return strings.Join(*l, ",") }

func (l *listFlags) Set(v string) error {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return errors.New("empty path pattern")
	}
	*l = append(*l, trimmed)
	return nil
}

func main() {
	var (
		hubURL        string
		token         string
		caCertPath    string
		targetID      string
		modeRaw       string
		ttl           time.Duration
		selfDestruct  bool
		noDefaultDeny bool
		showVersion   bool
		allowPaths    listFlags
		denyPaths     listFlags
		tags          = make(tagFlags)
	)

	flag.StringVar(&hubURL, "hub", "", "Hub WebSocket URL (e.g. wss://mcp.example.com/agent/ws or ws://host:9443/agent/ws)")
	flag.StringVar(&token, "token", "", "Short-lived enrollment token (or REVMCP_ENROLL_TOKEN env)")
	flag.StringVar(&caCertPath, "ca-cert", "", "Optional PEM CA certificate path for private/self-signed Hub TLS")
	flag.StringVar(&targetID, "target-id", "", "Optional target ID (defaults to enrollment token target or hostname)")
	flag.StringVar(&modeRaw, "mode", string(proto.ModeReadOnly), "Permission mode: readonly | restricted | full")
	flag.DurationVar(&ttl, "ttl", 0, "Optional auto-exit duration (e.g. 2h)")
	flag.BoolVar(&selfDestruct, "self-destruct-on-exit", false, "Remove agent binary from disk upon exit")
	flag.BoolVar(&noDefaultDeny, "no-default-deny", false, "Disable built-in sensitive path denylist for fs.read/fs.grep")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")
	flag.Var(&allowPaths, "allow-path", "Optional allowed file path glob/prefix for fs.read/fs.grep (repeatable)")
	flag.Var(&denyPaths, "deny-path", "Optional denied file path glob/prefix for fs.read/fs.grep (repeatable)")
	flag.Var(tags, "tag", "Optional target metadata tag in key=value format (repeatable)")
	flag.Parse()

	if showVersion {
		_, _ = fmt.Fprintf(os.Stdout, "revmcp-agent %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if token == "" {
		token = os.Getenv("REVMCP_ENROLL_TOKEN")
	}
	if hubURL == "" || token == "" {
		logger.Error("missing required flags: --hub and --token are required")
		os.Exit(2)
	}

	mode, err := proto.ParseMode(modeRaw)
	if err != nil {
		logger.Error("invalid mode", "err", err)
		os.Exit(2)
	}

	g, err := guard.New(mode)
	if err != nil {
		logger.Error("guard init failed", "err", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if ttl > 0 {
		var ttlCancel context.CancelFunc
		ctx, ttlCancel = context.WithTimeout(ctx, ttl)
		defer ttlCancel()
	}

	startedAt := time.Now().UTC()
	sys, _ := sysinfo.CollectSysInfo()
	hostname := ""
	kernel := ""
	inContainer := false
	if sys != nil {
		hostname = sys.Hostname
		kernel = sys.Kernel
		inContainer = sys.InContainer
	}
	if targetID == "" {
		targetID = hostname
	}

	execEngine := executor.New()
	sessions := executor.NewSessionPool(executor.SessionConfig{})
	defer sessions.CloseAll()

	fileReader := fsread.NewReader(fsread.Policy{
		AllowPaths:    allowPaths,
		DenyPaths:     denyPaths,
		NoDefaultDeny: noDefaultDeny,
	})

	var remoteSelfDestruct bool
	var client *tunnel.Client

	handler := func(rpcCtx context.Context, req proto.Request) (any, *proto.RPCError) {
		if err := g.CheckMethod(req.Method); err != nil {
			return nil, &proto.RPCError{Code: proto.ErrCodeModeDenied, Message: err.Error()}
		}

		switch req.Method {
		case proto.MethodAgentPing:
			active := 0
			if client != nil {
				active = client.ActiveRPCs()
			}
			return &proto.PingResult{
				Timestamp:     time.Now().UTC(),
				UptimeSeconds: int64(time.Since(startedAt).Seconds()),
				ActiveRPCs:    active,
			}, nil

		case proto.MethodSysInfo:
			info, err := sysinfo.CollectSysInfo()
			if err != nil {
				return nil, &proto.RPCError{Code: proto.ErrCodeInternal, Message: err.Error()}
			}
			return info, nil

		case proto.MethodProcList:
			var p proto.ProcListRequest
			if len(req.Params) > 0 {
				if err := json.Unmarshal(req.Params, &p); err != nil {
					return nil, &proto.RPCError{Code: proto.ErrCodeInvalidArgument, Message: err.Error()}
				}
			}
			res, err := sysinfo.ListProcesses(p)
			if err != nil {
				return nil, &proto.RPCError{Code: proto.ErrCodeInternal, Message: err.Error()}
			}
			return res, nil

		case proto.MethodNetSockets:
			res, err := sysinfo.ListSockets()
			if err != nil {
				return nil, &proto.RPCError{Code: proto.ErrCodeInternal, Message: err.Error()}
			}
			return res, nil

		case proto.MethodFSRead:
			var p proto.FSReadRequest
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, &proto.RPCError{Code: proto.ErrCodeInvalidArgument, Message: err.Error()}
			}
			res, err := fileReader.Read(p)
			if err != nil {
				code := proto.ErrCodeInternal
				if errors.Is(err, os.ErrNotExist) {
					code = proto.ErrCodeNotFound
				} else if errors.Is(err, fsread.ErrPathDenied) {
					code = proto.ErrCodePolicyDenied
				} else if errors.Is(err, fsread.ErrInvalidPath) {
					code = proto.ErrCodeInvalidArgument
				}
				return nil, &proto.RPCError{Code: code, Message: err.Error()}
			}
			return res, nil

		case proto.MethodFSGrep:
			var p proto.FSGrepRequest
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, &proto.RPCError{Code: proto.ErrCodeInvalidArgument, Message: err.Error()}
			}
			res, err := fileReader.Grep(p)
			if err != nil {
				code := proto.ErrCodeInternal
				if errors.Is(err, os.ErrNotExist) {
					code = proto.ErrCodeNotFound
				} else if errors.Is(err, fsread.ErrPathDenied) {
					code = proto.ErrCodePolicyDenied
				} else if errors.Is(err, fsread.ErrInvalidPath) {
					code = proto.ErrCodeInvalidArgument
				}
				return nil, &proto.RPCError{Code: code, Message: err.Error()}
			}
			return res, nil

		case proto.MethodCmdExec:
			var p proto.CmdExecRequest
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, &proto.RPCError{Code: proto.ErrCodeInvalidArgument, Message: err.Error()}
			}
			if err := g.CheckCommand(p.Command); err != nil {
				code := proto.ErrCodePolicyDenied
				if errors.Is(err, guard.ErrModeDenied) {
					code = proto.ErrCodeModeDenied
				}
				return nil, &proto.RPCError{Code: code, Message: err.Error()}
			}
			res, err := execEngine.Exec(rpcCtx, p)
			if err != nil {
				return nil, &proto.RPCError{Code: proto.ErrCodeInternal, Message: err.Error()}
			}
			return res, nil

		case proto.MethodSessionOpen:
			var p proto.SessionOpenRequest
			if len(req.Params) > 0 {
				if err := json.Unmarshal(req.Params, &p); err != nil {
					return nil, &proto.RPCError{Code: proto.ErrCodeInvalidArgument, Message: err.Error()}
				}
			}
			res, err := sessions.Open(rpcCtx, p)
			if err != nil {
				code := proto.ErrCodeInternal
				if errors.Is(err, executor.ErrMaxSessionsReached) {
					code = proto.ErrCodePolicyDenied
				}
				return nil, &proto.RPCError{Code: code, Message: err.Error()}
			}
			return res, nil

		case proto.MethodSessionExec:
			var p proto.SessionExecRequest
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, &proto.RPCError{Code: proto.ErrCodeInvalidArgument, Message: err.Error()}
			}
			res, err := sessions.Exec(rpcCtx, p)
			if err != nil {
				code := proto.ErrCodeInternal
				if errors.Is(err, executor.ErrSessionNotFound) {
					code = proto.ErrCodeNotFound
				}
				return nil, &proto.RPCError{Code: code, Message: err.Error()}
			}
			return res, nil

		case proto.MethodSessionClose:
			var p proto.SessionCloseRequest
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, &proto.RPCError{Code: proto.ErrCodeInvalidArgument, Message: err.Error()}
			}
			res, err := sessions.Close(rpcCtx, p)
			if err != nil {
				code := proto.ErrCodeInternal
				if errors.Is(err, executor.ErrSessionNotFound) {
					code = proto.ErrCodeNotFound
				}
				return nil, &proto.RPCError{Code: code, Message: err.Error()}
			}
			return res, nil

		case proto.MethodAgentShutdown:
			var p proto.ShutdownRequest
			if len(req.Params) > 0 {
				_ = json.Unmarshal(req.Params, &p)
			}
			if p.SelfDestruct {
				remoteSelfDestruct = true
			}
			logger.Info("received remote shutdown directive", "reason", p.Reason, "self_destruct", p.SelfDestruct)
			go func() {
				time.Sleep(100 * time.Millisecond)
				stop()
			}()
			return &proto.ShutdownResult{Accepted: true}, nil

		default:
			return nil, &proto.RPCError{Code: proto.ErrCodeUnsupported, Message: "unsupported method"}
		}
	}

	client, err = tunnel.NewClient(tunnel.Config{
		HubURL:     hubURL,
		Token:      token,
		CACertPath: caCertPath,
		AgentInfo: proto.AgentInfo{
			TargetID:    targetID,
			InstanceID:  randomHex(8),
			Hostname:    hostname,
			OS:          runtime.GOOS,
			Kernel:      kernel,
			Arch:        runtime.GOARCH,
			InContainer: inContainer,
			Mode:        mode,
			Version:     version,
			Tags:        tags,
			StartedAt:   startedAt,
		},
		Handler: handler,
		Logger:  logger,
	})
	if err != nil {
		logger.Error("tunnel client init failed", "err", err)
		os.Exit(2)
	}

	logger.Info("starting revmcp-agent", "version", version, "mode", mode, "ttl", ttl.String())
	if err := client.Run(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		logger.Error("agent exited with error", "err", err)
	}

	if selfDestruct || remoteSelfDestruct {
		if err := removeSelfBinary(); err != nil {
			logger.Warn("self-destruct failed", "err", err)
		} else {
			logger.Info("self-destruct completed")
		}
	}
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func removeSelfBinary() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err == nil && resolved != "" {
		exe = resolved
	}
	return os.Remove(exe)
}
