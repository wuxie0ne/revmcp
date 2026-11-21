# revmcp 阶段交付与验收

## 1. 分阶段实施与验收状态（DoD）

| 阶段 | 状态 | 交付物 | 核心验收标准（Definition of Done） |
| :--- | :---: | :--- | :--- |
| **Phase 0: 项目初始化** | ✅ 已完成 | 多模块仓库骨架、`mise` 工具链锁定、`proto` 帧与 DTO、`agent` 执行器/AST Guard 基础与单测、`hub` 配置/鉴权/审计/MCP 装配骨架、部署示例 | 1. `proto`/`agent`/`hub` 均通过 `go test -race`、`go vet`、`golangci-lint`；<br>2. `agent` 静态编译 `linux/amd64` 与 `linux/arm64` 成功且 `ldd` 为静态二进制；<br>3. `agent` 与 `proto` 零 MCP SDK 依赖。 |
| **Phase 1: 最小闭环（MVP）** | ✅ 已完成 | WSS/WS + Yamux 隧道双向通信、`/proc/mounts` 挂载点采集、自定义 `--ca-cert`、断线指数退避重置、`TraceID` 贯通、隧道重连与级联取消集成测试 | 1. Agent 支持 `wss://`（含私有 CA）与 `ws://` 自定义端口；<br>2. 断连后自动重连无重复节点；<br>3. `ldd revmcp-agent` 输出 `not a dynamic executable`。 |
| **Phase 2: 受控执行与安全** | ✅ 已完成 | Agent 文件路径黑白名单与默认高危路径保护（含符号链接防逃逸）、令牌桶限流、`/mcp/{target_id}` 隔离 Schema 与纵深防御测试 | 1. 前端取消后远端进程组 1 秒内无残留孤儿；<br>2. 大输出由 `HeadTailBuffer` 稳定截断；<br>3. `restricted` 模式拒绝全部 AST 绕过，默认拒绝 `/etc/shadow` 等敏感文件。 |
| **Phase 3: 会话与运维完善** | ✅ 已完成 | `shell_session` 持久化会话池（保留 `cd`/环境变量、随机 Sentinel 退出码、上限与空闲回收、零僵尸进程）、Hub Admin HTTP API 和 `revmcp-hub target` CLI、真实静态二进制自毁与 `--ttl` E2E 测试 | 会话保留工作目录与环境变量，空闲超时自动回收。远程自毁后进程退出，磁盘上的二进制已删除。 |
| **Phase 4: 渠道凭证管理** | ✅ 已完成 | 渠道签发、状态持久化、重显、轮换和吊销。统一使用渠道凭证接入，独立管理员认证，支持 `target kick --expired`。 | 并发同名拒绝、跨渠道同名隔离、吊销持久化、换钥后旧凭证拒绝、已有 MCP 会话的下一次调用在 Bearer 到期后收到 401。轮换后，批量下线仍按旧连接使用的凭证到期时间判断。 |

## 2. Phase 4 验收记录

- 阶段交付见 `bf259d9` 和 `5a84e9e`。后者移除旧版静态认证、离线签发和按 JTI 管理的接口。部署配置使用 `management.admin_token_sha256`，Agent 启动须提供 `--target-id`。
- 在 `5a84e9e` 提交前通过 `make test`、`make test-e2e`、`make vet`、`make lint`、`make build` 和 `make verify-static`。这一轮未重跑 Docker 兼容性镜像。
- [MCP 回归测试](../hub/internal/mcpserver/server_test.go)验证同一客户端会话跨过 Bearer 到期点后的拒绝行为。[真实 Agent 端到端测试](../hub/internal/e2e/channels_test.go)验证轮换以后只下线使用已过期凭证的连接。

## 3. 构建与部署入口

- [构建、验证与容器兼容性命令](../README.md#2-编译与验证)。
- [GitHub Actions 发布与本地打包](../README.md#版本发布)。
- [渠道部署模板](../deploy/hub.channels.example.yaml)。
- [Nginx 反代模板](../deploy/nginx.example.conf)。
