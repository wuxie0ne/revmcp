# revmcp — 轻量级 Go 反向 MCP 网关

`revmcp` 是一个面向受限 Linux 环境（精简/无 Shell 容器、老旧 CentOS 7 主机、NAT 内网隔离节点）的**一拖多反向 MCP 网关**，由极简静态 `Agent` 与中转 `Hub` 组成。

受限目标机只需主动向外发起出站 `WSS`/`WS` 连接，无需开放任何入站端口或安装 Node.js/Python 运行时，即可将安全的远程诊断与受控命令能力通过标准 **MCP Streamable HTTP** 协议暴露给本地 AI 客户端（Cursor、Claude Code、Claude Desktop 等）。

## 核心特性

- **轻 Agent + 重 Hub 架构**：`Agent` 仅约 `6.3MB`（`CGO_ENABLED=0` 全静态编译，已实测兼容 `Alpine 3.20` 与 `CentOS 7 / glibc 2.17`），不含任何 MCP 协议栈；升级工具定义或安全策略只需重启 `Hub`。
- **原生 `/proc` 诊断**：纯 Go 直接解析 `/proc`，即使容器内没有 `ps`/`ss`/`free`/`bash` 也能采集系统信息、挂载点、进程列表与监听端口。
- **一拖多路由与单机隔离**：支持 `/mcp` 聚合跨机排查，以及 `/mcp/{target_id}` 单机隔离（自动隐藏 `target_id` 参数，防止 AI 误操作其他主机）。
- **纵深安全防御**：
  - 北向 Bearer Token（SHA-256 恒定时间比对）+ Scope + `allowed_targets` Glob + 令牌桶限流；
  - 南向 HMAC-SHA256 短效 Enrollment Token + `jti` 吊销列表 + 异机 `instance_id` 抢占高危审计告警；
  - Agent 启动级硬锁 `--mode readonly|restricted|full`（`restricted` 使用 `mvdan.cc/sh/v3` AST 白名单解析，非正则黑名单）；
  - 文件读取拒绝设备/管道文件（防 `/dev/zero` 阻塞），默认内置高危凭据路径黑名单，并支持 `--allow-path` / `--deny-path`（含符号链接穿透检测）；
  - 全链路 JSONL 脱敏审计 + `<remote_output>` 防 Prompt Injection 边界包裹。
- **临时授权与零残留**：支持 `--ttl` 自动退出、Hub 远程下线/自毁（`--self-destruct` 删除磁盘二进制文件），且管理接口仅通过受 `admin` scope 保护的 HTTP API / CLI 提供，不暴露给 LLM。

## 架构与文档

- [需求文档（PRD）](docs/prd.md)
- [系统与详细设计文档](docs/design.md)
- [实现与部署计划](docs/implementation-plan.md)
- [AI 协作规范](AGENTS.md)

## 快速开始

### 1. 安装工具链（`mise`）

```bash
mise trust
mise install
(cd agent && mise install)
```

### 2. 编译与验证

```bash
# 运行全量单元测试（-race）、真实二进制 E2E 测试、静态检查与 Lint
make test
make test-e2e
make vet
make lint

# 编译 Hub 与静态 Linux Agent（amd64 / arm64）并验证静态链接
make build
make verify-static

# （可选）使用 Docker 验证 Alpine 与 CentOS 7 容器兼容性
docker build -f deploy/Dockerfile.compat-test --target alpine-check .
docker build -f deploy/Dockerfile.compat-test --target centos7-check .
```

### 3. 配置并启动 Hub

先为北向 AI 客户端或管理员生成高熵 Bearer Token 的 SHA-256 摘要，并填入配置文件（参考 [deploy/hub.example.yaml](deploy/hub.example.yaml)）：

```bash
printf '%s' 'replace-with-your-client-bearer-token' | sha256sum
```

签发南向短效节点注册 Token 并启动 Hub：

```bash
export REVMCP_SIGNING_SECRET="replace-with-strong-random-secret"

# 为目标机签发 2 小时有效的 readonly 注册 Token
ENROLL_TOKEN=$(./bin/revmcp-hub token gen \
  --secret "$REVMCP_SIGNING_SECRET" \
  --target prod-web-01 \
  --mode readonly \
  --ttl 2h)

# 方式 A：单端口模式（配合前置 Nginx 443 统一反代 /mcp 与 /agent/ws）
./bin/revmcp-hub serve --config deploy/hub.example.yaml

# 方式 B：南北向分端口隔离（/mcp 在 listen，/agent/ws 独立监听在自定义高位端口）
./bin/revmcp-hub serve \
  --config deploy/hub.example.yaml \
  --listen 127.0.0.1:8443 \
  --tunnel-listen 0.0.0.0:9443
```

> 生产环境可参考 [deploy/nginx.example.conf](deploy/nginx.example.conf) 配置前置 TLS 终结与反代。

### 4. 在目标机运行 Agent

将单文件二进制 `bin/revmcp-agent-linux-amd64`（或 `arm64`）拷贝至目标机直接运行：

```bash
# 走 HTTPS/WSS（公网或内网反代，支持 HTTPS_PROXY；内网自签证书可加 --ca-cert）
./revmcp-agent-linux-amd64 \
  --hub wss://mcp.example.com:9443/agent/ws \
  --ca-cert /path/to/private-ca.pem \
  --token "$ENROLL_TOKEN" \
  --mode readonly \
  --allow-path '/var/log/*' \
  --tag env=prod \
  --ttl 2h \
  --self-destruct-on-exit

# 或内网直连纯 HTTP 高位端口（ws://）
./revmcp-agent-linux-amd64 \
  --hub ws://10.0.0.10:9443/agent/ws \
  --token "$ENROLL_TOKEN" \
  --mode restricted \
  --ttl 1h
```

> 默认内置高危路径黑名单（`/etc/shadow`、`/proc/*/environ`、`/root/.ssh/*`、`/home/*/.ssh/*`、`/etc/kubernetes/pki/*` 等）；仅在明确需要时可通过 `--no-default-deny` 关闭。

### 5. 本地 AI 客户端接入（MCP Streamable HTTP）

在 Cursor / Claude Code / Claude Desktop 的 MCP 配置中添加远程 HTTP 服务（Hub 以 `Stateless: true` 模式运行，仅需标准 `POST` 请求）：

```json
{
  "mcpServers": {
    "revmcp-all": {
      "url": "https://mcp.example.com/mcp",
      "headers": {
        "Authorization": "Bearer <your-client-bearer-token>"
      }
    },
    "revmcp-prod-web-01": {
      "url": "https://mcp.example.com/mcp/prod-web-01",
      "headers": {
        "Authorization": "Bearer <your-client-bearer-token>"
      }
    }
  }
}
```

- `/mcp`：聚合端点，可调用 `list_targets` 并在多台授权目标机间切换联调。
- `/mcp/{target_id}`：单机隔离端点，工具 Schema 自动隐藏 `target_id`，严格锁定单一目标机。

### 6. 管理员运维操作（不暴露给 LLM）

需使用具备 `admin` scope 的 Bearer Token 调用 Admin API 或 CLI：

```bash
export REVMCP_ADMIN_TOKEN="<admin-bearer-token>"

# 查看在线节点列表（支持 --tag env=prod 过滤）
./bin/revmcp-hub target list --hub http://127.0.0.1:8443

# 远程下线目标机并触发磁盘二进制自毁
./bin/revmcp-hub target kick \
  --hub http://127.0.0.1:8443 \
  --target prod-web-01 \
  --reason "排查完成清理" \
  --self-destruct

# 吊销疑似泄露的南向注册 Token（按签发时输出的 jti）
./bin/revmcp-hub token revoke --hub http://127.0.0.1:8443 --jti <jti>
```

## 内置 MCP Tool 与权限矩阵

| Tool 名称 | 功能说明 | 所需北向 Scope | 目标机最低 `--mode` |
| :--- | :--- | :--- | :--- |
| `list_targets` | 列出当前在线且获授权的目标机 | `read` | 全部 |
| `get_system_info` | 纯 Go 采集 CPU/内存/负载/内核/挂载点 | `read` | `readonly` |
| `list_processes` | 纯 Go 采集 `/proc/[pid]` 进程列表（按 RSS 排序） | `read` | `readonly` |
| `list_listening_ports` | 纯 Go 采集 `/proc/net` 监听端口与连接统计 | `read` | `readonly` |
| `read_file` | 分块（`offset`）或尾部（`tail_lines`）受限读取文件 | `read` | `readonly` |
| `grep_file` | 流式正则检索文件（受匹配数与字节上限保护） | `read` | `readonly` |
| `exec_command` | 无状态执行单条非交互命令（支持取消与进程组查杀） | `exec:restricted`（目标为 `full` 时需 `exec:full`） | `restricted` / `full` |
| `shell_session` | 有状态持久化 Shell 会话（`open`/`run`/`close`） | `exec:session` | `full` |
