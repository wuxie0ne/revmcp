package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/revmcp/revmcp/hub/internal/admin"
	hubauth "github.com/revmcp/revmcp/hub/internal/auth"
	"github.com/revmcp/revmcp/hub/internal/channel"
	"github.com/revmcp/revmcp/hub/internal/config"
	"github.com/revmcp/revmcp/hub/internal/mcpserver"
	"github.com/revmcp/revmcp/hub/internal/policy"
	"github.com/revmcp/revmcp/hub/internal/registry"
	"github.com/revmcp/revmcp/hub/internal/tunnel"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("hub exited with error", "err", err)
			os.Exit(1)
		}
	case "token":
		if err := runToken(os.Args[2:]); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "channel":
		if err := runChannel(os.Args[2:]); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "file":
		if err := runFile(os.Args[2:]); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "target":
		if err := runTarget(os.Args[2:]); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "--version", "-version", "version":
		_, _ = fmt.Fprintf(os.Stdout, "revmcp-hub %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	default:
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	_, _ = fmt.Fprintln(os.Stderr, "Usage:")
	_, _ = fmt.Fprintln(os.Stderr, "  revmcp-hub serve --config <path> [--listen <addr>] [--tunnel-listen <addr>] [--accept-signing-key-change]")
	_, _ = fmt.Fprintln(os.Stderr, "  revmcp-hub token issue --config <path> --name <channel> [--profile <profile> | --allowed-target <rule>] [--scope <scope>] [--mode <mode>] [--agent-ttl <duration>] [--ttl <duration>]")
	_, _ = fmt.Fprintln(os.Stderr, "  revmcp-hub token list --config <path> [--channel <name> [--details | --show-secrets]]")
	_, _ = fmt.Fprintln(os.Stderr, "  revmcp-hub token rotate | revoke --config <path> --channel <name> --kind agent|mcp")
	_, _ = fmt.Fprintln(os.Stderr, "  revmcp-hub channel delete --config <path> --name <channel>")
	_, _ = fmt.Fprintln(os.Stderr, "  revmcp-hub target kick --config <path> --channel <name> --target <id> [--reason <msg>] [--self-destruct]")
	_, _ = fmt.Fprintln(os.Stderr, "  revmcp-hub target kick --config <path> --expired [--reason <msg>]")
	_, _ = fmt.Fprintln(os.Stderr, "  revmcp-hub file upload | download --endpoint <MCP URL> [--target <id>] --local <path> --remote <path> [--overwrite]")
	_, _ = fmt.Fprintln(os.Stderr, "  revmcp-hub version")
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var (
		configPath       string
		listenFlag       string
		tunnelListenFlag string
		acceptKeyChange  bool
	)
	fs.StringVar(&configPath, "config", "", "Path to hub YAML configuration file")
	fs.StringVar(&listenFlag, "listen", "", "Optional northbound/default listen address override (e.g. 127.0.0.1:8443)")
	fs.StringVar(&tunnelListenFlag, "tunnel-listen", "", "Optional dedicated southbound tunnel listen address (e.g. 0.0.0.0:9443)")
	fs.BoolVar(&acceptKeyChange, "accept-signing-key-change", false, "Accept changed channel signing keys and permanently revoke affected credentials")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if configPath == "" {
		return errors.New("--config is required")
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if listenFlag != "" {
		cfg.Listen = listenFlag
	}
	if tunnelListenFlag != "" {
		cfg.TunnelListen = tunnelListenFlag
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	store, err := channel.Open(cfg.Tokens.StatePath, cfg.AgentSigningSecret, cfg.Tokens.SigningSecret, acceptKeyChange)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	adminVerifier, err := hubauth.NewAdminBearerVerifier(cfg.Management.AdminTokenSHA256)
	if err != nil {
		return err
	}
	audit, err := policy.NewAuditLogger(cfg.AuditLogPath)
	if err != nil {
		return err
	}
	defer func() { _ = audit.Close() }()

	reg := registry.New()
	tunnelSrv := tunnel.NewServer(store, reg, audit, version, cfg.MaxInflightPerAgent, logger)
	mcpGW := mcpserver.NewGateway(version, reg, audit)
	if rl := policy.NewRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst); rl != nil {
		mcpGW.SetRateLimiter(rl)
	}
	adminHandler := admin.NewHandler(reg, store, audit)

	healthHandler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}

	splitTunnel := cfg.TunnelListen != "" && cfg.TunnelListen != cfg.Listen

	mainMux := http.NewServeMux()
	mcpGW.RegisterRoutes(mainMux, hubauth.NewChannelBearerVerifier(store))
	adminHandler.RegisterRoutes(mainMux, adminVerifier, cfg.Tokens)
	mainMux.HandleFunc("/healthz", healthHandler)
	if !splitTunnel {
		mainMux.Handle("/agent/ws", tunnelSrv)
	}

	servers := []*http.Server{
		{
			Addr:              cfg.Listen,
			Handler:           mainMux,
			ReadHeaderTimeout: 10 * time.Second,
		},
	}

	if splitTunnel {
		tunnelMux := http.NewServeMux()
		tunnelMux.Handle("/agent/ws", tunnelSrv)
		tunnelMux.HandleFunc("/healthz", healthHandler)
		servers = append(servers, &http.Server{
			Addr:              cfg.TunnelListen,
			Handler:           tunnelMux,
			ReadHeaderTimeout: 10 * time.Second,
		})
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, len(servers))
	for _, s := range servers {
		srv := s
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("listen %s: %w", srv.Addr, err)
				return
			}
			errCh <- nil
		}()
	}

	if splitTunnel {
		logger.Info("starting revmcp-hub", "version", version, "mcp_listen", cfg.Listen, "tunnel_listen", cfg.TunnelListen)
	} else {
		logger.Info("starting revmcp-hub", "version", version, "listen", cfg.Listen, "tunnel_listen", cfg.Listen)
	}

	var firstErr error
	select {
	case <-ctx.Done():
	case err := <-errCh:
		firstErr = err
		stop()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdownCtx)
	}
	return firstErr
}

func runToken(args []string) error {
	if len(args) < 1 {
		return errors.New("expected subcommand: token issue | list | rotate | revoke")
	}

	switch args[0] {
	case "issue":
		return runTokenIssue(args[1:])
	case "list":
		return runTokenList(args[1:])
	case "rotate":
		return runTokenChange(args[1:], "rotate")
	case "revoke":
		return runTokenChange(args[1:], "revoke")
	default:
		return fmt.Errorf("unknown token subcommand %q", args[0])
	}
}

func doAdminJSON(method, endpoint, bearerToken string, payload any) ([]byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(raw)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("hub returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return respBody, nil
}
