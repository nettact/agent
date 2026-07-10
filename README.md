# agent

NetTact 软件 Agent —— 部署在 Windows / Linux / macOS / NAS 上的**纯出站监控客户端**，绝不监听任何端口，所有数据主动上传（架构 §2.1 / §15.1）。Apache-2.0。

M1 已实现：
- `internal/platform/` — 平台 HAL；Windows 用 `GetAdaptersAddresses`（网卡/网关/DNS）与 `IcmpSendEcho`（网关 ping，**免管理员**、CGO-free），可交叉编译到 Linux。
- `internal/collector/` — interface + gateway-ping collector。
- `internal/uploader/` — gzip 批量上传。
- `internal/identity/` — 本地 agent 身份（M2 起换 ed25519 注册）。

近零配置运行：

```
go run ./cmd/nettact-agent --server http://localhost:8080 --interval 5s
```

依赖 [github.com/nettact/protocol](https://github.com/nettact/protocol)。本地多仓开发使用 `go.work`。
