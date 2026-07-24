# agent

NetTact 软件 Agent —— 部署在 Windows / Linux / macOS / NAS 上的**纯出站监控客户端**，绝不监听任何端口，所有数据主动上传（架构 §2.1 / §15.1）。Apache-2.0。

M1 已实现：
- `internal/platform/` — 平台 HAL；Windows 用 `GetAdaptersAddresses`（网卡/网关/DNS）与 `IcmpSendEcho`（网关 ping，**免管理员**、CGO-free），可交叉编译到 Linux。
- `internal/collector/` — interface + gateway-ping collector。
- `internal/conn/` — 到服务器的持久 WebSocket 连接（遥测上行 + 配置/快照请求下行，断线自动重连）。
- `internal/identity/` — 本地 agent 身份（M2 起换 ed25519 注册）。

近零配置运行（配置来自 YAML 配置文件与 `NETTACT_AGENT_*` 环境变量；除 `--config` 外无其它配置类命令行参数，另保留 `--help` / `--version`）：

```powershell
$env:NETTACT_AGENT_SERVER_URL   = "http://localhost:12450"
$env:NETTACT_AGENT_ENROLL_TOKEN_FILE = "C:\nettact\agent.token"   # 首次注册，优先用文件
go run ./cmd/nettact-agent
```

本地权限策略同样在配置中定义、进程内不可变、修改后需重启：

- `NETTACT_AGENT_PERMISSIONS`：显式权限列表，**整体替换**默认集（未设置时使用固定默认；`none` 仅保留必需功能）。永不支持 `*` / `all`。
- `NETTACT_AGENT_PROBE_ACCESS_MODE` / `_PROBE_ALLOWLIST` / `_PROBE_DENYLIST`：探测目标访问策略（allowlist / denylist，deny 优先；选择器 `scope:` / `cidr:` / `ip:` / `host:`）。

完整变量清单见 `nettact-agent --help`。

## 配置文件（YAML）

所有配置项都可写入一个 YAML 文件，键名与环境变量一一对应（如 `server_url` ↔ `NETTACT_AGENT_SERVER_URL`、`probe_access.mode` ↔ `NETTACT_AGENT_PROBE_ACCESS_MODE`）。校验、范围与互斥规则与环境变量路径完全复用，报错信息仍以对应的 `NETTACT_AGENT_*` 变量名给出定位。

- **优先级（从高到低）**：配置文件 > 环境变量 > 内置默认。同一项两处都设时，文件取值胜；未在文件中出现的项回落到环境变量。
- **定位顺序（命中即止）**：`--config <path>` 命令行参数 → `NETTACT_AGENT_CONFIG_FILE` 环境变量 → 工作目录 `./nettact-agent.yaml` → 平台惯例路径（Windows：`%ProgramData%\NetTact\agent.yaml`；其它：`/etc/nettact/agent.yaml`）。
- 经 `--config` 或 `NETTACT_AGENT_CONFIG_FILE` **显式指定**的文件不存在或不可读即启动失败；自动探测的默认路径缺失则静默改走纯环境变量。
- **显式指定但为空值**（`--config=`、`--config ""`、或设为空白的 `NETTACT_AGENT_CONFIG_FILE`）同样启动失败，而非回落到自动探测——指明了配置来源却留空几乎必是部署失误。
- 语法错误、未知键、非法取值均启动失败并给出文件名与行号/键名。
- 文件可能包含注册令牌（`enroll_token` / `enroll_token_file`），建议权限 `600`。修改配置后需重启 Agent（不支持热加载）。

完整键清单、默认值、范围与互斥说明见 [`agent.example.yaml`](./agent.example.yaml)：

```yaml
server_url: http://host:12450
permissions:
  - probe.icmp
  - probe.dns
probe_access:
  mode: allowlist
  allowlist: [scope:lan]
```

依赖 [github.com/nettact/protocol](https://github.com/nettact/protocol)。本地多仓开发使用 `go.work`。