# revmcp 实现与部署计划

## 1. 分阶段实施与验收状态（DoD）

| 阶段 | 状态 | 交付物 | 核心验收标准（Definition of Done） |
| :--- | :---: | :--- | :--- |
| **Phase 0: 项目初始化** | ✅ 已完成 | 多模块仓库骨架、`mise` 工具链锁定、`proto` 帧与 DTO、`agent` 执行器/AST Guard 基础与单测、`hub` 配置/鉴权/审计/MCP 装配骨架、部署示例 | 1. `proto`/`agent`/`hub` 均通过 `go test -race`、`go vet`、`golangci-lint`；<br>2. `agent` 静态编译 `linux/amd64` 与 `linux/arm64` 成功且 `ldd` 为静态二进制；<br>3. `agent` 与 `proto` 零 MCP SDK 依赖。 |
| **Phase 1: 最小闭环（MVP）** | ✅ 已完成 | WSS/WS + Yamux 隧道双向通信、`/proc/mounts` 挂载点采集、自定义 `--ca-cert`、断线指数退避重置、`TraceID` 贯通、隧道重连与级联取消集成测试 | 1. Agent 支持 `wss://`（含私有 CA）与 `ws://` 自定义端口；<br>2. 断连后自动重连无重复节点；<br>3. `ldd revmcp-agent` 输出 `not a dynamic executable`。 |
| **Phase 2: 受控执行与安全** | ✅ 已完成 | Agent 文件路径黑白名单与默认高危路径保护（含符号链接防逃逸）、令牌桶限流、`/mcp/{target_id}` 隔离 Schema 与纵深防御测试 | 1. 前端取消后远端进程组 1 秒内无残留孤儿；<br>2. 大输出由 `HeadTailBuffer` 稳定截断；<br>3. `restricted` 模式拒绝全部 AST 绕过，默认拒绝 `/etc/shadow` 等敏感文件。 |
| **Phase 3: 会话与运维完善** | ✅ 已完成 | `shell_session` 持久化会话池（保留 `cd`/环境变量、随机 Sentinel 退出码、上限与空闲回收、零僵尸进程）、Hub Admin HTTP API+ `revmcp-hub target` CLI、真实静态二进制自毁与 `--ttl` E2E 测试 | 1. `session` 保留 `cd` 与环境变量，空闲超时自动回收无僵尸进程；<br>2. 远程自毁后进程退出且磁盘二进制已删除；<br>3. `make test`、`make test-e2e`、`make vet`、`make lint`、`make verify-static` 全量通过。 |
| **Phase 4: 渠道凭证管理** | ✅ 已完成 | 预设和即时签发单机或通配渠道、有状态吊销与轮换、有效凭证重显、在线目标列表和渠道隔离路由 | 并发同名拒绝、跨渠道同名隔离、断开后重连、重启后持久化吊销、同名重建和换钥后旧凭证拒绝。全量检查及真实 Agent E2E 通过。 |

## 2. 编译与验证命令

```bash
# 安装工具链
mise trust
mise install
(cd agent && mise install)

# 全量单元测试、真实二进制 E2E 测试、静态检查与 Lint
make test
make test-e2e
make vet
make lint

# 跨平台静态构建与校验
make build
make verify-static

# 容器兼容性实测（已验证通过 alpine:3.20 与 centos:7）
docker build -f deploy/Dockerfile.compat-test --target alpine-check .
docker build -f deploy/Dockerfile.compat-test --target centos7-check .
```

## 3. 生产部署参考

- [渠道部署模板](../deploy/hub.channels.example.yaml)。
- Nginx 反代模板：`deploy/nginx.example.conf`
- CentOS 7 / Alpine 静态兼容性测试镜像：`deploy/Dockerfile.compat-test`
