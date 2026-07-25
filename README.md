# agent

NetTact 软件 Agent —— 部署在 Windows / Linux / macOS / NAS 上的**纯出站监控客户端**,绝不监听任何端口,所有数据主动上传(架构 §2.1 / §15.1)。Apache-2.0。

M1 已实现:
- `internal/platform/` — 平台 HAL;Windows 用 `GetAdaptersAddresses`(网卡/网关/DNS)与 `IcmpSendEcho`(网关 ping,**免管理员**、CGO-free),可交叉编译到 Linux。
- `internal/collector/` — interface + gateway-ping collector。
- `internal/conn/` — 到服务器的持久 WebSocket 连接(遥测上行 + 配置/快照请求下行,断线自动重连)。
- `internal/identity/` — 本地 agent 身份(M2 起换 ed25519 注册)。

## 配置

**推荐用 YAML 配置文件**(带注释模板见 [`agent.example.yaml`](./agent.example.yaml));
每个键与一个 `NETTACT_AGENT_*` 环境变量一一对应,优先级:**配置文件 > 环境变量 >
内置默认**。唯一的配置类命令行参数是 `--config`(另保留 `--help` / `--version`)。

```yaml
# nettact-agent.yaml(工作目录自动发现;建议 chmod 600)
server_url: http://localhost:12450
enroll_token: "<控制台签发的一次性令牌>"   # 仅首次注册需要
```

```bash
go run ./cmd/nettact-agent            # 自动发现 ./nettact-agent.yaml
```

完整参考(全部键/变量、默认值与范围、定位顺序、注册流程、权限策略
`permissions` 的整体替换语义、探测目标访问控制 `probe_access`、平台能力差异)
见 **[docs/agent-config.md](../docs/agent-config.md)**;单一事实来源为
`nettact-agent --help`。

依赖 [github.com/nettact/protocol](https://github.com/nettact/protocol)。本地多仓开发使用 `go.work`。
