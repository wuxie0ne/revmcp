# AGENTS.md — revmcp (Go Reverse MCP Gateway)

## 1. Architecture Invariants (DO NOT VIOLATE)

1. **Thin Agent, Thick Hub**: `github.com/modelcontextprotocol/go-sdk` lives **ONLY in `hub/`**. NEVER import any MCP SDK into `agent/` or `proto/`.
2. **Zero-Dependency Static Agent**: `agent/` MUST compile with `CGO_ENABLED=0` into a static Linux binary (`ldd` reports `not a dynamic executable`). Never add CGO dependencies to `agent/`.
3. **Outbound-Only Agent**: `agent/` dials outbound WSS to `hub/` (any configured port, honoring `HTTPS_PROXY`). Plain WS is supported for local and private-network deployments. Never open a listening socket on the target machine.
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

Also run `make test-e2e` for changes to credentials, channel routing, Agent registration or shutdown, or the Hub/Agent CLI and deployment paths those flows depend on.

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
- Protect `/mcp` and `/mcp/{target_id}` with `auth.RequireBearerToken`. Check the channel MCP Bearer's current validity and expiration on every HTTP request. Read caller identity and scopes from `req.Extra.TokenInfo`. Reserve `AllowMissingExpiration: true` for the separate management Bearer authenticated against `management.admin_token_sha256`.
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
3. **Fail Closed**: Reject registration with invalid or expired channel enrollment tokens. Reject MCP requests with invalid or expired channel MCP Bearers. Reject unrecognized modes, missing `TokenInfo`, and AST parse errors.
4. **Prompt Injection Boundary**: Wrap all untrusted remote outputs in `<remote_output ...>...</remote_output>` (escaping any embedded `</remote_output>`).
5. **Audit & Logging**: Emit a structured JSONL audit entry (redacting secrets) for every `tools/call` (allow or deny). Never log raw Bearer/Enrollment tokens. Write operational logs via `log/slog` to `stderr` only.
6. **Atomic Contract Changes**: Update `proto/` -> `agent/` -> `hub/` -> tests together when changing RPC contracts.

## 6. Feature Changes and Removal

- Start from the current requirement and the callers it serves. Reuse an existing path if it can meet the requirement. When a new design replaces an old workflow, keep one supported path for that use case and remove the superseded implementation in the same change.
- Keep a compatibility path only for an identified supported caller, deployment, or stored-data format with a concrete need. Document what depends on it. For temporary compatibility, also record the migration steps and the condition for removal.
- Trace the old path through its entry points and dependencies before deleting it. Remove obsolete CLI flags, API routes, configuration fields, helpers, tests, fixtures, and examples that exist solely for that path. Preserve shared behavior, supported data, and independent security checks. Test the replacement through its normal entry point and cover rejection of removed inputs where it matters.
- Apply this rule to the components affected by the requirement. For example, channel credentials replaced static MCP authentication and offline Agent enrollment, so the old routes, commands, and configuration were removed together. The separate administrator credential still serves the channel management API.

## 7. Documentation and Milestone Closeout

- Before closing a phase or creating a commit that changes behavior, configuration, CLI, APIs, RPC contracts, security policy, or deployment, review the affected docs and include any updates in the same commit. Update the minimum set that describes the change.
- Use [README.md](README.md) for setup and operator commands, [docs/prd.md](docs/prd.md) for product requirements and scope, and [docs/design.md](docs/design.md) for contracts, architecture, and security semantics. Keep shipped configuration examples in [deploy/](deploy/).
- Record phase deliverables, acceptance criteria, and verification evidence in [docs/implementation-plan.md](docs/implementation-plan.md). Close a phase after verification and label any checks that were skipped. Keep command examples in the README and link to them from the plan.
- Include breaking changes and their operator impact in the relevant docs and commit message. Check examples against the built CLI's help, configuration templates, and tests. Keep local configuration, credential values, and token state out of docs and commits.
