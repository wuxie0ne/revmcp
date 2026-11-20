# AGENTS.md — revmcp (Go Reverse MCP Gateway)

## 1. Architecture Invariants (DO NOT VIOLATE)

1. **Thin Agent, Thick Hub**: `github.com/modelcontextprotocol/go-sdk` lives **ONLY in `hub/`**. NEVER import any MCP SDK into `agent/` or `proto/`.
2. **Zero-Dependency Static Agent**: `agent/` MUST compile with `CGO_ENABLED=0` into a static Linux binary (`ldd` reports `not a dynamic executable`). Never add CGO dependencies to `agent/`.
3. **Outbound-Only Agent**: `agent/` only dials outbound HTTPS/WSS to `hub/` (any configured port, honoring `HTTPS_PROXY`). Never open a listening socket on the target machine.
4. **Module Boundaries**:
   - `proto/`: Go 1.23, Go standard library ONLY. Shared length-prefixed framing & RPC DTOs.
   - `agent/`: Go 1.23, minimal deps (`coder/websocket`, `hashicorp/yamux`, `mvdan.cc/sh/v3` pinned to `v3.11.0` while Go 1.23 is retained).
   - `hub/`: Go 1.25+, uses `github.com/modelcontextprotocol/go-sdk` (v1.8.0+).

## 2. Toolchain (`mise`)

- Always run Go/linter commands via `mise exec --` (or `make`, which invokes `mise exec --` inside each module). Never install/upgrade Go or linters globally outside `mise.toml`.
- Keep `GOTOOLCHAIN=local`. Sub-modules `proto/mise.toml` and `agent/mise.toml` pin Go 1.23 and set `GOWORK=off` so root `go.work` (Go 1.25) does not block Go 1.23 builds.
- If a tool is missing, run `mise trust && mise install && (cd agent && mise install)`.

## 3. Verification Commands

Run before completing any code change:

```bash
make test           # go test -race -v ./... across proto, agent, hub
make vet            # go vet ./... across proto, agent, hub
make lint           # golangci-lint run --config ../.golangci.yml ./... across all modules
make build          # Hub + static Linux amd64 & arm64 Agent binaries
make verify-static  # Verifies static linkage (ldd) and binary size of agent
```

When changing `agent/internal/executor` or `agent/internal/guard`, tests MUST cover:
- Timeout & cancellation process-group kill (`syscall.Kill(-pid, SIGKILL)` leaves zero orphan children).
- `HeadTailBuffer` truncation under > 1MB output.
- Restricted-mode AST bypasses (`;`, `&&`, `||`, `|`, `$()`, backticks, `>`, `>>`, `<()`, dangerous flags).

## 4. Critical Pitfalls & Implementation Rules

### 4.1 `coder/websocket` + `hashicorp/yamux`
- Call `wsConn.SetReadLimit(4 * 1024 * 1024)` before `websocket.NetConn(...)` (default 32KB breaks RPC frames).
- NEVER pass `http.Request.Context()` into `websocket.NetConn(...)`; use a dedicated `context.WithCancel(context.Background())` cancelled on teardown.
- Configure `yamux`: `EnableKeepAlive: true`, `KeepAliveInterval: 10 * time.Second`, `ConnectionWriteTimeout: 15 * time.Second`, `LogOutput: io.Discard`.
- **1-stream-per-RPC & cascade cancel**: Hub opens one stream per RPC and calls `stream.Close()` on `ctx.Done()`. Agent MUST spawn a `stream.Read` watcher goroutine after reading the request frame to cancel the handler context immediately on EOF/RST.

### 4.2 Official MCP Go SDK (`hub/`)
- Register tools with typed `mcp.AddTool(server, &mcp.Tool{...}, handler)` using `jsonschema` struct tags and accurate `ToolAnnotations` (`ReadOnlyHint`, `DestructiveHint`).
- Use `mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}` (note: stateless mode returns `405` for `GET`/`DELETE`) and share an `mcp.NewSchemaCache()` across per-target isolated `/mcp/{target_id}` servers.
- Protect `/mcp` and `/mcp/{target_id}` with `auth.RequireBearerToken`. For static API keys without `Expiration`, pass `&auth.RequireBearerTokenOptions{AllowMissingExpiration: true}` (SDK v1.8.0+ rejects zero `Expiration` by default). Read caller identity/scopes from `req.Extra.TokenInfo`.
- Return operational failures (offline target, permission denied, non-zero exit diagnostics) as MCP tool errors / structured results rather than raw HTTP 500s.
- Hub supports custom southbound tunnel ports via `tunnel_listen` / `--tunnel-listen` (when separate from `listen`, isolate `/agent/ws` onto `tunnel_listen` and keep `/mcp` strictly on `listen`).

### 4.3 Agent Execution, `/proc`, and File Reads (`agent/`)
- Probe `/bin/bash` and fall back to `/bin/sh`; never assume `/bin/bash` exists.
- For `exec_command`, set `cmd.Stdin = nil` and `SysProcAttr{Setpgid: true}`; kill `-pid` with `SIGKILL` on timeout/cancel.
- `sys.info`, `proc.list`, and `net.sockets` MUST parse `/proc` directly in pure Go—NEVER shell out to `ps`, `free`, `ss`, or `netstat`.
- Truncate/cap all output on the Agent side; never use unbounded `io.ReadAll` on outputs, files, or network frames. Reject directories, FIFOs, sockets, and device files (e.g., `/dev/zero`) in `fs.read`/`fs.grep`.

## 5. Security Red Lines (Non-Negotiable)

1. **Defense in Depth**: Enforce authorization/mode checks in BOTH `hub/` (token scopes + `allowed_targets` glob) AND `agent/` (`--mode readonly|restricted|full`).
2. **No Regex Blacklists**: `restricted` mode MUST parse commands with `mvdan.cc/sh/v3/syntax` AST and enforce a strict allowlist.
3. **Fail Closed**: Reject invalid/expired Enrollment Tokens, unrecognized modes, missing `TokenInfo`, or AST parse errors.
4. **Prompt Injection Boundary**: Wrap all untrusted remote outputs in `<remote_output ...>...</remote_output>` (escaping any embedded `</remote_output>`).
5. **Audit & Logging**: Emit a structured JSONL audit entry (redacting secrets) for every `tools/call` (allow or deny). Never log raw Bearer/Enrollment tokens. Write operational logs via `log/slog` to `stderr` only.
6. **Atomic Contract Changes**: Update `proto/` -> `agent/` -> `hub/` -> tests together when changing RPC contracts.
