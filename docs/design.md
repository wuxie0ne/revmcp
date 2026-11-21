# revmcp 系统与详细设计文档

## 1. 核心架构决策：轻 Agent（RPC）+ 重 Hub（MCP）

```text
+--------------------+   HTTPS (MCP Streamable HTTP)   +----------------------------------------------+
|  本地 AI 客户端    | <==============================> |                 Hub (Go 1.25+)               |
|  Cursor / Claude   |   auth.RequireBearerToken       |  +----------------------------------------+  |
+--------------------+                                 |  | MCP Layer (modelcontextprotocol/go-sdk)|  |
                                                       |  |  - Stateless StreamableHTTPHandler     |  |
                                                       |  |  - Tool Registry + Schema + Annotations|  |
                                                       |  +-------------------+--------------------+  |
                                                       |                      |                       |
                                                       |  +-------------------v--------------------+  |
                                                       |  | Core Engine                            |  |
                                                       |  |  - Policy Guard (Scope / Target/Limits)|  |
                                                       |  |  - Audit Logger (JSONL)                |  |
                                                       |  |  - Agent Registry (target_id -> Conn)  |  |
                                                       |  +-------------------+--------------------+  |
                                                       |                      |                       |
                                                       |  +-------------------v--------------------+  |
                                                       |  | Tunnel Manager (WSS + hashicorp/yamux) |  |
                                                       |  +-------------------+--------------------+  |
                                                       +----------------------|-----------------------+
                                                                              | 主动出站 WSS/WS (自定义端口)
                                                                              | Yamux Multiplexing
                                                       +----------------------v-----------------------+
                                                       |            Agent (Static Binary)             |
                                                       |  - Yamux Client (Open Register / Accept RPC) |
                                                       |  - Local Guard (--mode readonly/restricted)  |
                                                       |  - Native /proc Collector (No Shell Needed)  |
                                                       |  - File Chunk/Grep Reader (Max 128KB)        |
                                                       |  - Exec Engine (Setpgid + Stdin=nil + Cap)   |
                                                       |  - Session Pool (Optional Stateful Shell)    |
                                                       +----------------------------------------------+
```

### 多模块解耦
- `proto/`（Go 1.23+，零外部依赖）：定义南向长度前缀帧协议与所有 RPC DTO。
- `agent/`（Go 1.23+，`CGO_ENABLED=0` 静态编译）：仅引入 `coder/websocket`、`hashicorp/yamux`、`mvdan.cc/sh/v3`。
- `hub/`（Go 1.25+）：引入官方 `github.com/modelcontextprotocol/go-sdk`，负责 MCP 协议适配、鉴权、路由与审计。

## 2. 传输层与多路复用设计（WSS + Yamux）

### 连接与角色分工
- TCP/WSS 层由 Agent 主动拨号连接 Hub（`GET /agent/ws` 升级 WebSocket）。Hub 支持单端口复用（`listen` 同时承接 `/mcp` 与 `/agent/ws`）或通过 `tunnel_listen` / `--tunnel-listen` 将南向隧道独立监听在任意自定义端口；Agent 侧通过 `--hub wss://host:<port>/agent/ws` 连接对应端口。
- Yamux 层约定：**Agent = `yamux.Client`**（建连后主动打开首条流发送 `agent.register` 握手），**Hub = `yamux.Server`**（接收首条注册流并在工具调用时主动 `OpenStream()` 下发 RPC）。
- 双方均可 `OpenStream()`，固定一端 Client 一端 Server 避免 Stream ID 奇偶冲突。

### `coder/websocket` + `yamux` 关键铁律
1. **独立生命周期 Context**：使用 `context.WithCancel(context.Background())` 传入 `websocket.NetConn`，绝不使用 `http.Request.Context()`。
2. **显式调大 ReadLimit**：包装前调用 `wsConn.SetReadLimit(4 * 1024 * 1024)`，避免默认 32KB 截断导致连接断开。
3. **保活配置**：`yamux.Config` 开启 `EnableKeepAlive: true`、`KeepAliveInterval: 10 * time.Second`、`ConnectionWriteTimeout: 15 * time.Second`，并将 `LogOutput` 重定向至 `io.Discard`（避免正常关闭刷屏）。

### 级联取消机制
- 每条 `yamux.Stream` 承载一次独立 RPC（1 Request + 1 Response）。
- Hub 在 `ctx.Done()` 时立即调用 `stream.Close()`；
- Agent 端 RPC 分发器在读完请求帧后启动轻量 watcher goroutine 监听该 `stream` 的 `EOF`/重置事件，一旦对端关闭流立即 `cancel()` 当前 handler 的 `context`，触发 `syscall.Kill(-pid, syscall.SIGKILL)` 查杀进程组。

## 3. 南向内部 RPC 协议（长度前缀 + JSON）

```text
+------------------+----------------------------------------+
|  Length (4B BE)  |          Payload (JSON UTF-8)          |
+------------------+----------------------------------------+
```

- 单帧最大上限：`2MB`（`proto.MaxFrameSize`），超限立即拒绝以防 OOM。
- `Response` 使用结构化 `RPCError{Code, Message, Retryable}`，便于 Hub 准确映射为 MCP Tool 错误与审计决策。

### RPC 方法表

| Method | 方向 | 说明 | Agent `--mode` 最低要求 |
| :--- | :--- | :--- | :--- |
| `agent.register` | Agent -> Hub | 建连后首条流发送协议版本、`--target-id` 指定的目标名和主机元数据 | 全部 |
| `agent.ping` | Hub -> Agent | 应用层健康探测 | 全部 |
| `sys.info` | Hub -> Agent | 纯 Go 读 `/proc` 返回 CPU/Mem/Load/Disk/Uptime | `readonly` |
| `proc.list` | Hub -> Agent | 纯 Go 读 `/proc/[pid]` 返回进程列表 | `readonly` |
| `net.sockets` | Hub -> Agent | 纯 Go 读 `/proc/net/tcp{,6},udp{,6}` 返回监听端口与连接统计 | `readonly` |
| `fs.read` | Hub -> Agent | 分块或尾部读取常规/伪文件（拒绝阻塞设备与 FIFO） | `readonly` |
| `fs.grep` | Hub -> Agent | 流式正则检索文件（限制单行扫描与最大匹配数） | `readonly` |
| `cmd.exec` | Hub -> Agent | 无状态执行单条命令（`restricted` 下走 AST 白名单校验） | `restricted` / `full` |
| `session.open/exec/close` | Hub -> Agent | 持久化有状态 Shell 会话管理 | `full` |
| `agent.shutdown` | Hub -> Agent | 远程踢下线，可选 `self_destruct: true` 清理自身二进制 | 全部 |

## 4. 北向 MCP 协议与 Admin 接口契约

### MCP 端点
- 使用 `github.com/modelcontextprotocol/go-sdk` 的 `mcp.NewStreamableHTTPHandler(..., &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})`（注：`Stateless: true` 下 `GET`/`DELETE` 返回 `405 Method Not Allowed`），并在单机隔离 Server 间复用 `mcp.NewSchemaCache()`。
- MCP 路由通过 `auth.RequireBearerToken` 验证渠道 Bearer，处理器通过 `req.Extra.TokenInfo` 校验 scope 与目标规则。
- 路由策略：
  - `/mcp`：聚合端点，所有远程工具均接收 `target_id`；
  - `/mcp/{target_id}`：单机隔离端点，工具 Schema 隐藏 `target_id`，在路由层绑定目标并校验权限，防止跨机误操作。
- 所有来自目标机的不可信文本输出必须包裹在 `<remote_output target="..." exit_code="..." truncated="...">...</remote_output>` 边界标签中（并对内嵌 `</remote_output>` 转义）。

### Admin HTTP API

管理路由挂载在北向 `listen`。渠道管理使用独立的管理员 Bearer。Hub 将其 SHA-256 摘要与 `management.admin_token_sha256` 恒定时间比对。

| 方法和路径 | 行为 |
| --- | --- |
| `POST /admin/channels` | 按策略创建渠道并签发两枚凭证。同名返回 `409`。 |
| `GET /admin/channels` | 返回带在线目标的渠道元数据数组。 |
| `GET /admin/channels/{channel}` | 返回单个渠道元数据对象。 |
| `POST /admin/channels/{channel}/reveal` | 返回指定渠道仍有效的凭证原值。 |
| `POST /admin/channels/{channel}/rotate/{kind}` | 轮换该类凭证并返回新值。 |
| `POST /admin/channels/{channel}/revoke/{kind}` | 吊销该类凭证。 |
| `POST /admin/channels/{channel}/targets/{target_id}/shutdown` | 下线该渠道内的目标。 |
| `POST /admin/targets/expired/shutdown` | 按各在线连接注册时的凭证到期时间，向所有符合条件的 Agent 请求退出。返回逐目标结果。 |
| `DELETE /admin/channels/{channel}` | 吊销整组凭证并断开该渠道的在线目标。 |

`kind` 取 `agent` 或 `mcp`。渠道管理响应带 `Cache-Control: no-store`。目标下线请求可指定 `reason` 和 `self_destruct`。

## 5. Agent 命令执行、会话池与安全防爆

1. **进程组隔离与查杀**：`cmd.Stdin = nil` + `SysProcAttr{Setpgid: true}` + 取消/超时后 `syscall.Kill(-pid, syscall.SIGKILL)`。
2. **首尾保留截断缓冲区（`HeadTailBuffer`）**：默认上限 `32KB`（最大 `128KB`），保留头部 `25%` + 环形尾部 `75%`，避免内存膨胀。
3. **AST 受限命令校验（`--mode restricted`）**：使用 `mvdan.cc/sh/v3/syntax` 解析完整 AST，禁止命令替换、进程替换、重定向写盘、非白名单命令、子命令危险参数（如 `find -exec`、`dmesg -C`、危险 `docker`/`kubectl` 子命令），解析失败一律 Fail-Closed。
4. **有状态会话池（`--mode full`）**：每次命令使用唯一随机 Sentinel 边界标记解析退出码，保留 `cd` 与环境变量，受最大并发会话数与空闲超时自动回收约束，退出或超时查杀整个进程组并 `Wait()` 回收确保零僵尸进程。

## 6. 安全与审计模型

- **南向注册认证**：Hub 校验 HMAC-SHA256 注册 Token 的签名、有效期、吊销状态和 Agent 模式。渠道注册要求目标名匹配渠道规则，并拒绝同渠道重名。
- **传输灵活性**：Hub 保持纯 HTTP（配合前置 Nginx/Caddy 终结 TLS 或内网高位端口直连），支持通过 `tunnel_listen` / `--tunnel-listen` 将南向 `/agent/ws` 隔离到独立端口；Agent 原生支持 `wss://`（可选 `--ca-cert` 加载内网自签 CA）及 `ws://`（纯 HTTP + 高位端口）。
- **北向认证与路由**：渠道 Bearer 使用独立密钥签名，获准访问本渠道内匹配目标规则的节点。调用须符合 scope 和目标规则，限流键按渠道、调用者和目标区分。
- **Agent 文件路径防线**：`fs.read` / `fs.grep` 在拒绝目录、FIFO、Socket 与设备文件之外，默认内置高危凭据路径黑名单（`/etc/shadow`、`/proc/*/environ`、`/root/.ssh/*`、`/home/*/.ssh/*` 等），支持 `--allow-path`、`--deny-path`（含符号链接穿透解析检查）及 `--no-default-deny`。
- **结构化 JSONL 审计**：每条 `tools/call` 与 Admin 操作（无论放行或拒绝）写入 `ts`, `trace_id`, `user`, `channel_id`（渠道操作）, `target_id`, `tool`, `args_redacted`, `decision`, `reason`, `exit_code`, `duration_ms`, `truncated`，`trace_id` 透传至 Agent RPC，绝不记录原始 Token。

### 渠道状态和注册顺序

- Hub 使用不可复用的渠道 ID。在线注册表按 `(channel_id, target_id)` 索引。
- 新连接校验凭证和目标规则，预占名称后发送有超时的注册响应，成功后标记在线。同渠道的注册与删除、Agent 凭证变更串行协调。网络回包期间，其他渠道仍可管理。
- 本地 JSON 状态文件保存签发元数据和吊销状态。Hub 对状态文件加进程锁，更新时同步并原子替换。管理员可重显仍有效的凭证，Hub 通过已保存的元数据和签名密钥重现原值。
- MCP Bearer 被吊销后，后续请求被拒绝。Agent 注册 Token 被吊销后，后续注册被拒绝，已有连接继续在线。删除渠道会断开其在线连接。同名重建分配新 ID。
- Hub 拒绝意外的签名密钥变化。使用 `--accept-signing-key-change` 确认后，受影响的渠道凭证被持久化吊销，再由管理员轮换。
