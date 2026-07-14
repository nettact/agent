# agent

NetTact 软件 Agent —— 部署在 Windows / Linux / macOS / NAS 上的**纯出站监控客户端**，绝不监听任何端口，所有数据主动上传（架构 §2.1 / §15.1）。Apache-2.0。

M1 已实现：
- `internal/platform/` — 平台 HAL；Windows 用 `GetAdaptersAddresses`（网卡/网关/DNS）与 `IcmpSendEcho`（网关 ping，**免管理员**、CGO-free），可交叉编译到 Linux。
- `internal/collector/` — interface + gateway-ping collector。
- `internal/conn/` — 到服务器的持久 WebSocket 连接（遥测上行 + 配置/快照请求下行，断线自动重连）。
- `internal/identity/` — 本地 agent 身份（M2 起换 ed25519 注册）。

近零配置运行（配置全部来自 `NETTACT_AGENT_*` 环境变量，**不再有命令行参数**；仅保留 `--help` / `--version`）：

```powershell
$env:NETTACT_AGENT_SERVER_URL   = "http://localhost:8080"
$env:NETTACT_AGENT_ENROLL_TOKEN_FILE = "C:\nettact\agent.token"   # 首次注册，优先用文件
go run ./cmd/nettact-agent
```

本地权限策略同样由环境变量定义、进程内不可变、修改后需重启：

- `NETTACT_AGENT_PERMISSIONS`：显式权限列表，**整体替换**默认集（未设置时使用固定默认；`none` 仅保留必需功能）。永不支持 `*` / `all`。
- `NETTACT_AGENT_PROBE_ACCESS_MODE` / `_PROBE_ALLOWLIST` / `_PROBE_DENYLIST`：探测目标访问策略（allowlist / denylist，deny 优先；选择器 `scope:` / `cidr:` / `ip:` / `host:`）。

完整变量清单见 `nettact-agent --help`。

依赖 [github.com/nettact/protocol](https://github.com/nettact/protocol)。本地多仓开发使用 `go.work`。
