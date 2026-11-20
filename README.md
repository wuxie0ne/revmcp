# revmcp — Lightweight Reverse MCP Gateway

`revmcp` is a lightweight one-to-many reverse MCP gateway written in Go for restricted Linux environments (legacy CentOS 7 hosts, minimal/distroless containers, and NAT-isolated nodes).

## Architecture

- **Thin Agent (`agent/`)**: Static `CGO_ENABLED=0` Linux binary (Go 1.23+, zero dynamic library dependencies). Dials outbound `WSS` (port 443, supports `HTTPS_PROXY`), multiplexes RPC streams with `hashicorp/yamux`, enforces local `--mode readonly|restricted|full`, parses `/proc` natively in pure Go, and caps/truncates output before transmitting.
- **Thick Hub (`hub/`)**: Go 1.25+ gateway using the official `github.com/modelcontextprotocol/go-sdk`. Exposes stateless **MCP Streamable HTTP** (`/mcp` aggregated and `/mcp/{target_id}` isolated) protected by `auth.RequireBearerToken`, policy enforcement, prompt-injection boundary tagging, and JSONL audit logging.
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
# Run tests, vet, and lint across all modules
make test
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

# Start Hub (optionally bind southbound tunnel to a custom port with --tunnel-listen)
./bin/revmcp-hub serve --config deploy/hub.example.yaml --tunnel-listen 0.0.0.0:9443
```

### 4. Run Agent on a Restricted Target

```bash
./bin/revmcp-agent-linux-amd64 \
  --hub wss://mcp.example.com:9443/agent/ws \
  --token "$ENROLL_TOKEN" \
  --mode readonly \
  --ttl 2h \
  --self-destruct-on-exit
```
