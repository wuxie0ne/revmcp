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
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/revmcp/revmcp/hub/internal/admin"
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
	_, _ = fmt.Fprintln(os.Stderr, "  revmcp-hub serve --config <path> [--listen <addr>] [--tunnel-listen <addr>]")
	_, _ = fmt.Fprintln(os.Stderr, "  revmcp-hub token gen --target <id> [--mode readonly|restricted|full] [--ttl 2h] [--secret <secret> | --config <path>]")
	_, _ = fmt.Fprintln(os.Stderr, "  revmcp-hub token revoke --hub <url> --token <admin-bearer> --jti <jti>")
	_, _ = fmt.Fprintln(os.Stderr, "  revmcp-hub target list --hub <url> --token <admin-bearer> [--tag k=v]")
	_, _ = fmt.Fprintln(os.Stderr, "  revmcp-hub target kick --hub <url> --token <admin-bearer> --target <id> [--reason <msg>] [--self-destruct]")
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
	for _, jti := range cfg.RevokedJTIs {
		signer.Revoke(jti)
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
	tunnelSrv := tunnel.NewServer(signer, reg, audit, version, cfg.MaxInflightPerAgent, logger)
	mcpGW := mcpserver.NewGateway(version, reg, audit)
	if rl := policy.NewRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst); rl != nil {
		mcpGW.SetRateLimiter(rl)
	}
	adminHandler := admin.NewHandler(reg, signer, audit)

	healthHandler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}

	splitTunnel := cfg.TunnelListen != "" && cfg.TunnelListen != cfg.Listen

	mainMux := http.NewServeMux()
	mcpGW.RegisterRoutes(mainMux, verifier)
	adminHandler.RegisterRoutes(mainMux, verifier)
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
		return errors.New("expected subcommand: token gen | token revoke")
	}

	switch args[0] {
	case "gen":
		return runTokenGen(args[1:])
	case "revoke":
		return runTokenRevoke(args[1:])
	default:
		return fmt.Errorf("unknown token subcommand %q (expected gen or revoke)", args[0])
	}
}

func runTokenGen(args []string) error {
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
	if err := fs.Parse(args); err != nil {
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

func runTokenRevoke(args []string) error {
	fs := flag.NewFlagSet("token revoke", flag.ExitOnError)
	var (
		hubURL string
		token  string
		jti    string
	)
	fs.StringVar(&hubURL, "hub", "http://127.0.0.1:8443", "Hub base HTTP URL")
	fs.StringVar(&token, "token", "", "Admin Bearer token (or REVMCP_ADMIN_TOKEN env)")
	fs.StringVar(&jti, "jti", "", "Enrollment token JTI to revoke")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if token == "" {
		token = os.Getenv("REVMCP_ADMIN_TOKEN")
	}
	if token == "" || strings.TrimSpace(jti) == "" {
		return errors.New("--token and --jti are required")
	}

	body, err := doAdminJSON(http.MethodPost, strings.TrimRight(hubURL, "/")+"/admin/tokens/revoke", token, admin.RevokePayload{JTI: jti})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "%s\n", strings.TrimSpace(string(body)))
	return nil
}

func runTarget(args []string) error {
	if len(args) < 1 {
		return errors.New("expected subcommand: target list | target kick")
	}

	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("target list", flag.ExitOnError)
		var (
			hubURL string
			token  string
			tag    string
		)
		fs.StringVar(&hubURL, "hub", "http://127.0.0.1:8443", "Hub base HTTP URL")
		fs.StringVar(&token, "token", "", "Admin Bearer token (or REVMCP_ADMIN_TOKEN env)")
		fs.StringVar(&tag, "tag", "", "Optional tag filter (key=value)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if token == "" {
			token = os.Getenv("REVMCP_ADMIN_TOKEN")
		}
		if token == "" {
			return errors.New("--token (or REVMCP_ADMIN_TOKEN) is required")
		}

		endpoint := strings.TrimRight(hubURL, "/") + "/admin/targets"
		if tag != "" {
			endpoint += "?tag=" + url.QueryEscape(tag)
		}
		body, err := doAdminJSON(http.MethodGet, endpoint, token, nil)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(os.Stdout, "%s\n", strings.TrimSpace(string(body)))
		return nil

	case "kick":
		fs := flag.NewFlagSet("target kick", flag.ExitOnError)
		var (
			hubURL       string
			token        string
			targetID     string
			reason       string
			selfDestruct bool
		)
		fs.StringVar(&hubURL, "hub", "http://127.0.0.1:8443", "Hub base HTTP URL")
		fs.StringVar(&token, "token", "", "Admin Bearer token (or REVMCP_ADMIN_TOKEN env)")
		fs.StringVar(&targetID, "target", "", "Target ID to disconnect/shutdown")
		fs.StringVar(&reason, "reason", "operator requested shutdown", "Reason recorded in audit log")
		fs.BoolVar(&selfDestruct, "self-destruct", false, "Also delete the agent binary from disk on exit")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if token == "" {
			token = os.Getenv("REVMCP_ADMIN_TOKEN")
		}
		if token == "" || strings.TrimSpace(targetID) == "" {
			return errors.New("--token and --target are required")
		}

		endpoint := strings.TrimRight(hubURL, "/") + "/admin/targets/" + url.PathEscape(targetID) + "/shutdown"
		body, err := doAdminJSON(http.MethodPost, endpoint, token, admin.ShutdownPayload{
			Reason:       reason,
			SelfDestruct: selfDestruct,
		})
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(os.Stdout, "%s\n", strings.TrimSpace(string(body)))
		return nil

	default:
		return fmt.Errorf("unknown target subcommand %q (expected list or kick)", args[0])
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

	resp, err := http.DefaultClient.Do(req)
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
