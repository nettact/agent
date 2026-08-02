# NetTact Agent

[English](./README.md) | 简体中文

NetTact Agent 是安装在被监控设备上的轻量级采集端。它从设备所在的位置执行网络探测、采集主机与网络状态，并把结果主动推送到 NetTact Server。

它适合家庭网络、小型办公室、软路由、NAS 和分散在不同地点的主机。Agent 不开放入站端口，只需要能够访问 NetTact Server，因此通常无需配置端口转发，也能在 NAT、防火墙和动态 IP 环境中工作。

## 为什么使用 Agent

- **数据更接近真实体验**：探测在终端或站点内执行，可以看到当地网关、DNS、Wi-Fi、出口和目标服务的实际质量。
- **纯出站连接**：Agent 通过持久连接接收监控配置并上传结果，不监听任何端口。
- **断网不丢数据**：遥测数据先写入本地 WAL，连接恢复后继续上传。
- **集中配置**：监控目标由控制台下发，无需逐台编辑探测任务。
- **权限边界清晰**：本地权限策略决定 Agent 最多能采集什么；目标访问策略决定探测可以访问哪些地址。
- **跨平台**：支持 Windows、Linux 和 macOS，并提供原生服务与 Docker 部署方式。
- **低带宽**：默认使用 Protobuf 批量传输，也可切换为 JSON 便于排查。

## 可以监控什么

- ICMP 延迟、丢包、抖动与路径诊断
- DNS 解析、TCP 连接、TLS 握手和 HTTP 可用性
- 默认网关、网络接口、路由、邻居与 NAT 状态
- Wi-Fi 连接、信号强度、链路速率（以操作系统能力为准）
- CPU、内存、磁盘、负载、网络吞吐、温度等主机指标
- 进程和连接快照，以及故障发生时的现场诊断
- 通过 SOCKS5、HTTP CONNECT 或 WireGuard 出口执行指定监控

实际可用能力取决于操作系统、本地权限策略和运行权限。Agent 会向控制台报告“支持、已授权、实际可用”状态，不会用伪造的零值代替无法采集的数据。

## 安装、配置与运维

Agent 的安装与运维说明统一维护在 NetTact 用户文档：

- [部署 NetTact Server](https://nettact.org/zh/deploy)：一键部署、首次登录、远程 Agent 接入、升级、备份、HTTPS 与排障。
- [Agent 配置](https://nettact.org/zh/agent-config)：Windows、Linux、macOS 和 Docker 安装，注册令牌，YAML 与环境变量，运行状态、更新和故障排查。
- [权限参考](https://nettact.org/zh/permissions)：权限预设、平台支持、探测目标访问控制和每项权限的含义。

配置文件示例仍可在仓库中的 [`agent.example.yaml`](./agent.example.yaml) 查看。实际安装命令、配置项和运维步骤请以用户文档与 `nettact-agent --help` 为准，README 不重复维护这些易变化内容。

## 从源码构建

本项目使用 Go 1.25。NetTact 各 Go 模块应放在同一工作区，由根目录 `go.work` 解析本地依赖：

```bash
go build ./...
go test ./...
go build -o nettact-agent ./cmd/nettact-agent
```

运行时也可以作为 Go 库导入 [`agentrt`](./agentrt)，独立 Agent 和 NetTact Desktop 使用的是同一套采集运行时。

## 许可证

[Apache License 2.0](./LICENSE)
