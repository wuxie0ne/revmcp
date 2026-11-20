# revmcp 实现与部署计划

## 1. 分阶段实施与验收标准（DoD）

| 阶段 | 交付物 | 核心验收标准（Definition of Done） |
| :--- | :--- | :--- |
| **Phase 0: 项目初始化** | 多模块仓库骨架、`mise` 工具链锁定、`proto` 帧与 DTO、`agent` 执行器/AST Guard 基础与单测、`hub` 配置/鉴权/审计/MCP 装配骨架、部署示例 | 1. `proto`/`agent`/`hub` 均通过 `go test -race`、`go vet`、`golangci-lint`；<br>2. `agent` 静态编译 `linux/amd64` 与 `linux/arm64` 成功且 `ldd` 为静态二进制；<br>3. `agent` 与 `proto` 零 MCP SDK 依赖。 |
| **Phase 1: 最小闭环（MVP）** | WSS/Yamux 隧道双向通信 + `sys.info`/`proc.list`/`fs.read` + Hub `/mcp` 聚合接口 + Bearer 鉴权 | 1. 本地 AI 客户端可连 Hub 查看到 Alpine / CentOS 7 容器内的进程与日志；<br>2. 断网 10 秒恢复后 Agent 自动重连无重复节点；<br>3. `ldd revmcp-agent` 输出 `not a dynamic executable`。 |
| **Phase 2: 受控执行与安全** | `exec_command` 端到端链路 + 取消联动 + AST `restricted` 全量单测 + JSONL 审计 + `/mcp/{target_id}` 隔离路由 | 1. 运行 `sleep 60` 时前端取消，目标机 1 秒内无残留进程；<br>2. 运行 `cat /dev/zero` 或 50MB 文件，内存波动 < 10MB 且准确截断；<br>3. `restricted` 模式下各类 AST 绕过均被拒绝。 |
| **Phase 3: 会话与运维完善** | `shell_session` 池（上限 + 空闲回收）+ `fs.grep` + `net.sockets` + `--ttl` & 远程自毁 + Admin API / CLI | 1. `session` 保留 `cd` 与环境变量，空闲超时自动回收无僵尸进程；<br>2. 触发远程自毁后进程退出且磁盘二进制已删除；<br>3. 全量 `go test -race ./...` 通过。 |

## 2. 编译与验证命令

```bash
# 安装工具链
mise trust
mise install
(cd agent && mise install)

# 全量测试、静态检查与 Lint
make test
make vet
make lint

# 跨平台静态构建与校验
make build
make verify-static
```

## 3. 生产部署参考

- Hub 配置模板：`deploy/hub.example.yaml`
- Nginx 反代模板：`deploy/nginx.example.conf`
- CentOS 7 / Alpine 静态兼容性测试镜像：`deploy/Dockerfile.compat-test`
