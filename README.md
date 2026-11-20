# revmcp — Lightweight Reverse MCP Gateway

`revmcp` is a lightweight one-to-many reverse MCP gateway written in Go for restricted Linux environments (legacy CentOS 7 hosts, minimal/distroless containers, and NAT-isolated nodes).

## Architecture

- **Thin Agent (`agent/`)**: Static `CGO_ENABLED=0` Linux binary (Go 1.23+, zero dynamic library dependencies). Dials outbound `WSS`/`WS` on any configured port (supports `HTTPS_PROXY` and custom `--ca-cert`), multiplexes RPC streams with `hashicorp/yamux`, enforces local `--mode readonly|restricted|full` + path allow/deny policies, parses `/proc` natively in pure Go, and caps/truncates output before transmitting.
- **Thick Hub (`hub/`)**: Go 1.25+ gateway using the official `github.com/modelcontextprotocol/go-sdk`. Exposes stateless **MCP Streamable HTTP** (`/mcp` aggregated and `/mcp/{target_id}` isolated) plus authenticated Admin HTTP endpoints (`/admin/*`, never exposed as MCP tools to LLMs), protected by `auth.RequireBearerToken`, rate limiting, `jti` revocation, prompt-injection boundary tagging, and JSONL audit logging.
- **Shared Wire Protocol (`proto/`)**: Go 1.23+, standard library only. Length-prefixed JSON RPC frames and shared DTOs.

## Documentation

- [Product Requirements (PRD)](docs/prd.md)
- [System & Detailed Design](docs/design.md)
- [Implementation & Deployment Plan](docs/implementation-plan.md)
- [AI Agent Rules](AGENTS.md)

## Quick Start

### 1. Install Toolchains (`mise`)

```bash
mise trust
mise install
(cd agent && mise install)
```

### 2. Build & Test

```bash
# Run unit tests, real-binary E2E tests, vet, and lint across all modules
make test
make test-e2e
make vet
make lint

# Build Hub and static Agent binaries (amd64 & arm64)
make build
make verify-static
```

### 3. Generate an Enrollment Token & Run Hub

```bash
export REVMCP_SIGNING_SECRET="replace-with-strong-random-secret"

# Generate a short-lived enrollment token for a target
./bin/revmcp-hub token gen \
  --secret "$REVMCP_SIGNING_SECRET" \
  --target prod-web-01 \
  --mode readonly \
  --ttl 2h

# Start Hub (optionally bind southbound tunnel to a dedicated custom port)
./bin/revmcp-hub serve --config deploy/hub.example.yaml --tunnel-listen 0.0.0.0:9443
```

### 4. Run Agent on a Restricted Target

```bash
# Over TLS with public or private CA (--ca-cert), or plain ws:// on an internal high port
./bin/revmcp-agent-linux-amd64 \
  --hub wss://mcp.example.com:9443/agent/ws \
  --ca-cert /path/to/private-ca.pem \
  --token "$ENROLL_TOKEN" \
  --mode readonly \
  --allow-path '/var/log/*' \
  --ttl 2h \
  --self-destruct-on-exit
```

> By default, `fs.read` and `fs.grep` deny high-value credential paths (`/etc/shadow`, `/proc/*/environ`, `/root/.ssh/*`, `/home/*/.ssh/*`, `/etc/kubernetes/pki/*`). Pass `--no-default-deny` only when explicitly required.

### 5. Admin Operations (Not Exposed to LLMs)

```bash
export REVMCP_ADMIN_TOKEN="<admin-bearer-token>"

# List online targets
./bin/revmcp-hub target list --hub http://127.0.0.1:8443

# Remotely disconnect a target and delete its binary from disk
./bin/revmcp-hub target kick --hub http://127.0.0.1:8443 --target prod-web-01 --self-destruct

# Revoke a leaked enrollment token by JTI
./bin/revmcp-hub token revoke --hub http://127.0.0.1:8443 --jti <jti>
```
