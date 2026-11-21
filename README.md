# revmcp — 轻量级 Go 反向 MCP 网关

`revmcp` 是一个面向受限 Linux 环境（精简/无 Shell 容器、老旧 CentOS 7 主机、NAT 内网隔离节点）的**一拖多反向 MCP 网关**，由极简静态 `Agent` 与中转 `Hub` 组成。

受限目标机只需主动向外发起出站 `WSS`/`WS` 连接，无需开放任何入站端口或安装 Node.js/Python 运行时，即可将安全的远程诊断与受控命令能力通过标准 **MCP Streamable HTTP** 协议暴露给本地 AI 客户端（Cursor、Claude Code、Claude Desktop 等）。

## 核心特性

- **轻 Agent + 重 Hub 架构**：`Agent` 仅约 `6.3MB`（`CGO_ENABLED=0` 全静态编译，已实测兼容 `Alpine 3.20` 与 `CentOS 7 / glibc 2.17`），不含任何 MCP 协议栈；升级工具定义或安全策略只需重启 `Hub`。
- **原生 `/proc` 诊断**：纯 Go 直接解析 `/proc`，即使容器内没有 `ps`/`ss`/`free`/`bash` 也能采集系统信息、挂载点、进程列表与监听端口。
- **渠道凭证管理**：按单机或通配目标一次签发两枚凭证，支持查看在线目标、重显有效凭证、轮换和吊销。
- **一拖多路由与单机隔离**：支持 `/mcp` 聚合跨机排查，以及 `/mcp/{target_id}` 单机隔离（自动隐藏 `target_id` 参数，防止 AI 误操作其他主机）。
- **纵深安全防御**：
  - 北向签名渠道 Bearer，按 Scope 和目标规则授权，并支持令牌桶限流；
  - 南向 HMAC-SHA256 短效注册 Token，渠道内拒绝同名在线连接，按渠道和凭证类型吊销；
  - Agent 启动级硬锁 `--mode readonly|restricted|full`（`restricted` 使用 `mvdan.cc/sh/v3` AST 白名单解析，非正则黑名单）；
  - 文件读取拒绝设备/管道文件（防 `/dev/zero` 阻塞），默认内置高危凭据路径黑名单，并支持 `--allow-path` / `--deny-path`（含符号链接穿透检测）；
  - 全链路 JSONL 脱敏审计 + `<remote_output>` 防 Prompt Injection 边界包裹。
- **临时授权与清理**：Agent 支持 `--ttl` 自动退出，管理员可通过 HTTP API 或 CLI 远程下线目标，也可在单目标下线时要求删除 Agent 可执行文件。

## 文档索引

- [需求与范围（PRD）](docs/prd.md)
- [架构、接口与安全设计](docs/design.md)
- [阶段交付与验收](docs/implementation-plan.md)
- [开发协作与提交前文档规则](AGENTS.md)
- [版本发布](#版本发布)和 [MIT 许可证](LICENSE)

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

### 3. 配置 Hub 并签发渠道凭证

渠道将 Agent 注册 Token 与 AI 客户端的 MCP Bearer 绑定到同一目标规则。复制[渠道配置模板](deploy/hub.channels.example.yaml)，在 Hub 和管理终端加载对应的凭证。

```bash
cp deploy/hub.channels.example.yaml hub.channels.local.yaml

# 首次设置时生成，并将这些值保存在部署使用的凭证存储中。
export REVMCP_SIGNING_SECRET="$(openssl rand -hex 32)"
export REVMCP_MCP_SIGNING_SECRET="$(openssl rand -hex 32)"
export REVMCP_ADMIN_TOKEN="$(openssl rand -hex 32)"
export REVMCP_ADMIN_TOKEN_SHA256="$(
  printf '%s' "$REVMCP_ADMIN_TOKEN" | sha256sum | cut -d ' ' -f 1
)"
```

Hub 启动时读取两把签名密钥和 `management.admin_token_sha256` 指定的管理员 Bearer 摘要。管理终端读取管理员 Bearer 原值 `REVMCP_ADMIN_TOKEN`，并从同一配置的 `management.hub_url` 取得 Hub 地址。重启时加载已保存的值。状态文件路径相对于 YAML 所在目录，由一个 Hub 进程持有，启动前需准备可写的父目录。

模板默认在 `127.0.0.1:8443` 上启动，MCP 和 Agent 隧道共用监听端口。需要独立的 Agent 隧道端口时，在模板里设置 `tunnel_listen`，例如 `"0.0.0.0:9443"`。跨机器接入可通过 TLS 反代。管理命令可以在 Hub 主机上使用回环地址。参见 [Nginx 反代模板](deploy/nginx.example.conf)。

```bash
# 启动 Hub
./bin/revmcp-hub serve --config hub.channels.local.yaml

# 另开一个已加载管理员凭证的终端，按预设策略签发
./bin/revmcp-hub token issue --config hub.channels.local.yaml --name channel-01 --profile single
./bin/revmcp-hub token issue --config hub.channels.local.yaml --name channel-02 --profile fleet

# 也可以临时指定策略
./bin/revmcp-hub token issue --config hub.channels.local.yaml \
  --name mcp-remote-99 --scope read --allowed-target remote-99 --ttl 24h
```

`--mode` 控制 Agent 的最高运行模式。两种签发有效期及 Agent 运行时限见[凭证与连接的生命周期](#凭证与连接的生命周期)。

### 4. 在目标机运行 Agent

将单文件二进制 `bin/revmcp-agent-linux-amd64`（或 `arm64`）拷贝至目标机。下面以 `single` 预设的 `remote-99` 为例，使用签发结果里的 `enrollment_token`。

```bash
export REVMCP_ENROLL_TOKEN='<channel-01 的 enrollment_token>'

# 走 HTTPS/WSS（公网或内网反代，支持 HTTPS_PROXY；内网自签证书可加 --ca-cert）
./revmcp-agent-linux-amd64 \
  --hub wss://mcp.example.com:9443/agent/ws \
  --ca-cert /path/to/private-ca.pem \
  --target-id remote-99 \
  --mode readonly \
  --allow-path '/var/log/*' \
  --tag env=prod \
  --ttl 2h \
  --self-destruct-on-exit

# 或在 Hub 主机上用模板的默认端口联调
./revmcp-agent-linux-amd64 \
  --hub ws://127.0.0.1:8443/agent/ws \
  --target-id remote-99 \
  --mode readonly \
  --ttl 1h
```

> 默认内置高危路径黑名单（`/etc/shadow`、`/proc/*/environ`、`/root/.ssh/*`、`/home/*/.ssh/*`、`/etc/kubernetes/pki/*` 等）；仅在明确需要时可通过 `--no-default-deny` 关闭。

使用 `fleet` 时，可以在两台目标机上用 `channel-02` 的注册 Token，分别指定 `--target-id open-1` 和 `--target-id open-2`。Hub 直接拒绝同渠道的同名在线连接。网络闪断后，Agent 会在旧连接被 Hub 的 keepalive 清理后按退避策略重连。不同渠道可以各有一个 `open-1`。通配符注册 Token 的持有者可以声明本渠道内任意匹配的空闲名称。

### 5. 本地 AI 客户端接入（MCP Streamable HTTP）

在客户端的 MCP 配置中添加远程 HTTP 服务，请求头使用对应渠道签发的 `mcp_bearer`。Hub 使用无状态 Streamable HTTP，支持标准 `POST` 请求。在 Hub 主机上联调时可使用 `http://127.0.0.1:8443/mcp`。

```json
{
  "mcpServers": {
    "revmcp-all": {
      "url": "https://mcp.example.com/mcp",
      "headers": {
        "Authorization": "Bearer <channel-01 的 mcp_bearer>"
      }
    },
    "revmcp-remote-99": {
      "url": "https://mcp.example.com/mcp/remote-99",
      "headers": {
        "Authorization": "Bearer <channel-01 的 mcp_bearer>"
      }
    }
  }
}
```

- `/mcp`：聚合端点，可调用 `list_targets` 并在多台授权目标机间切换联调。
- `/mcp/{target_id}`：单机隔离端点，工具 Schema 自动隐藏 `target_id`，严格锁定单一目标机。

## 渠道凭证管理

```bash
# 每个渠道一行，显示目标规则、Agent 最高模式、注册凭证到期时间和在线目标
./bin/revmcp-hub token list --config hub.channels.local.yaml
# 只查看有效凭证元数据
./bin/revmcp-hub token list --config hub.channels.local.yaml --channel channel-01 --details
# 重新获取指定渠道当前有效的凭证原值（管理员）
./bin/revmcp-hub token list --config hub.channels.local.yaml --channel channel-01 --show-secrets
# 轮换或吊销指定类型（agent 或 mcp）
./bin/revmcp-hub token rotate --config hub.channels.local.yaml --channel channel-01 --kind mcp
./bin/revmcp-hub token revoke --config hub.channels.local.yaml --channel channel-01 --kind agent
# 对单个在线节点请求退出
./bin/revmcp-hub target kick --config hub.channels.local.yaml --channel channel-02 --target open-1
# 请求所有使用已过期注册凭证接入的在线 Agent 退出
./bin/revmcp-hub target kick --config hub.channels.local.yaml --expired
# 退出时同时删除该节点上的 Agent 二进制
./bin/revmcp-hub target kick --config hub.channels.local.yaml --channel channel-02 --target open-1 --self-destruct
# 删除渠道、吊销两类凭证并断开该渠道全部连接，随后可用原名重建
./bin/revmcp-hub channel delete --config hub.channels.local.yaml --name channel-02
```

Hub 可从签发元数据和签名密钥重现原凭证。列表默认隐藏原值，`--show-secrets` 只返回仍有效的凭证。Hub 发现签名密钥与状态文件不一致时会拒绝启动。确认换钥时，用新密钥和 `serve --config hub.channels.local.yaml --accept-signing-key-change` 启动一次，永久吊销受影响的渠道凭证，再通过 `token rotate` 签发对应类型的新凭证。

### 凭证与连接的生命周期

| 时限 | 设置方式 | 到期后的行为 |
| --- | --- | --- |
| Agent 注册凭证 | `token issue --agent-ttl` | 新连接和重连收到 HTTP 401。已经建立的隧道继续在线。 |
| MCP Bearer | `token issue --ttl` | 使用该凭证的新 MCP 请求收到 HTTP 401，包括已有 AI 会话发起的请求。 |
| Agent 运行时限 | 启动 Agent 时设置 `--ttl` | 从进程启动时计时。到期后 Agent 退出，隧道断开。 |

吊销 Agent 注册凭证也会阻止新连接和重连。管理员可用 `target kick` 下线单个在线目标，或用 `target kick --expired` 扫描所有渠道并下线使用已过期注册凭证接入的 Agent。批量操作按每条连接注册时的凭证到期时间判断，轮换出的新凭证有自己的到期时间。命令返回逐目标结果，任一 Agent 未接受退出请求时返回非零退出码。

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

## 版本发布

[Release 工作流](.github/workflows/release.yml)收到 `vMAJOR.MINOR.PATCH` 标签后，使用仓库固定的 mise 工具链运行测试、真实 Agent 端到端测试、静态检查及静态链接检查，通过后构建并发布 GitHub Release。手动运行时留空 `release_tag` 即可预演同一套检查和打包流程，产物从该次 Actions 运行下载。

每次正式发布提供三个 `.tar.gz` 归档和 `SHA256SUMS`。

| 归档 | 平台 | 内容 |
| --- | --- | --- |
| `revmcp-hub-<版本>-linux-amd64.tar.gz` | Linux amd64 | Hub、渠道配置模板、Nginx 反代示例 |
| `revmcp-agent-<版本>-linux-amd64.tar.gz` | Linux amd64 | 静态 Agent |
| `revmcp-agent-<版本>-linux-arm64.tar.gz` | Linux arm64 | 静态 Agent |

每个归档还包含 README、项目的 [MIT 许可证](LICENSE)和所用第三方依赖的许可文件。将三个归档和校验文件下载到同一目录后运行 `sha256sum -c SHA256SUMS`。

本地预打包使用 `make release VERSION=v0.1.0`，文件生成在 `bin/release/v0.1.0/`。正式发布前，先把发布工作流和版本变更提交并推送到 `main`。在 GitHub Actions 手动运行 **Release**，检查通过后给已验证的提交打标签并推送：

```bash
git tag -a v0.1.0 -m "revmcp v0.1.0"
git push origin refs/tags/v0.1.0
```

如果标签已推送而发布尚未成功，可在默认分支手动运行 **Release**，把现有标签填入 `release_tag`。工作流会使用默认分支的发布定义重新构建该标签指向的提交，发布前再次校验远端标签指向。
