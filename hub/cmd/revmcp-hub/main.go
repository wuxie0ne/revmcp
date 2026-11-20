package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	hubauth "github.com/revmcp/revmcp/hub/internal/auth"
	"github.com/revmcp/revmcp/hub/internal/config"
	"github.com/revmcp/revmcp/hub/internal/mcpserver"
	"github.com/revmcp/revmcp/hub/internal/policy"
	"github.com/revmcp/revmcp/hub/internal/registry"
	"github.com/revmcp/revmcp/hub/internal/tunnel"
	"github.com/revmcp/revmcp/proto"
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
	case "--version", "-version", "version":
		_, _ = fmt.Fprintf(os.Stdout, "revmcp-hub %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	default:
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	_, _ = fmt.Fprintln(os.Stderr, "Usage:")
	_, _ = fmt.Fprintln(os.Stderr, "  revmcp-hub serve --config <path> [--listen <addr>] [--tunnel-listen <addr>]")
	_, _ = fmt.Fprintln(os.Stderr, "  revmcp-hub token gen --target <id> [--mode readonly|restricted|full] [--ttl 2h] [--secret <secret> | --config <path>]")
	_, _ = fmt.Fprintln(os.Stderr, "  revmcp-hub version")
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var (
		configPath       string
		listenFlag       string
		tunnelListenFlag string
	)
	fs.StringVar(&configPath, "config", "", "Path to hub YAML configuration file")
	fs.StringVar(&listenFlag, "listen", "", "Optional northbound/default listen address override (e.g. 127.0.0.1:8443)")
	fs.StringVar(&tunnelListenFlag, "tunnel-listen", "", "Optional dedicated southbound tunnel listen address (e.g. 0.0.0.0:9443)")
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

	signer, err := hubauth.NewEnrollmentSigner(cfg.AgentSigningSecret)
	if err != nil {
		return err
	}
	verifier, err := hubauth.NewStaticBearerVerifier(cfg.Clients)
	if err != nil {
		return err
	}
	audit, err := policy.NewAuditLogger(cfg.AuditLogPath)
	if err != nil {
		return err
	}
	defer func() { _ = audit.Close() }()

	reg := registry.New()
	tunnelSrv := tunnel.NewServer(signer, reg, version, cfg.MaxInflightPerAgent, logger)
	mcpGW := mcpserver.NewGateway(version, reg, audit)

	healthHandler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}

	splitTunnel := cfg.TunnelListen != "" && cfg.TunnelListen != cfg.Listen

	mainMux := http.NewServeMux()
	mcpGW.RegisterRoutes(mainMux, verifier)
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
	if len(args) < 1 || args[0] != "gen" {
		return errors.New("expected subcommand: token gen")
	}

	fs := flag.NewFlagSet("token gen", flag.ExitOnError)
	var (
		configPath string
		secret     string
		targetID   string
		modeRaw    string
		ttl        time.Duration
	)
	fs.StringVar(&configPath, "config", "", "Path to hub YAML configuration file (reads agent_signing_secret)")
	fs.StringVar(&secret, "secret", "", "Signing secret (falls back to REVMCP_SIGNING_SECRET env)")
	fs.StringVar(&targetID, "target", "", "Target ID to bind into the enrollment token")
	fs.StringVar(&modeRaw, "mode", string(proto.ModeReadOnly), "Maximum allowed mode: readonly | restricted | full")
	fs.DurationVar(&ttl, "ttl", 2*time.Hour, "Token validity duration")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	if secret == "" && configPath != "" {
		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}
		secret = cfg.AgentSigningSecret
	}
	if secret == "" {
		secret = os.Getenv("REVMCP_SIGNING_SECRET")
	}

	signer, err := hubauth.NewEnrollmentSigner(secret)
	if err != nil {
		return err
	}
	mode, err := proto.ParseMode(modeRaw)
	if err != nil {
		return err
	}

	tok, claims, err := signer.Issue(targetID, mode, ttl)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(os.Stdout, "%s\n", tok)
	_, _ = fmt.Fprintf(os.Stderr, "issued enrollment token target=%s max_mode=%s jti=%s exp=%s\n",
		claims.TargetID, claims.MaxMode, claims.JTI, time.Unix(claims.Exp, 0).UTC().Format(time.RFC3339))
	return nil
}
