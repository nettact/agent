# NetTact Agent

English | [简体中文](./README-zh.md)

NetTact Agent is a lightweight collector installed on monitored devices. It runs network probes from the device's actual location, collects host and network health, and actively pushes the results to NetTact Server.

It is designed for home networks, small offices, routers, NAS devices, and machines spread across multiple locations. The Agent opens no inbound ports and only needs outbound access to NetTact Server, so it works naturally behind NAT, firewalls, and dynamic IP addresses.

## Why NetTact Agent

- **Measures the real user path**: probes see the local gateway, DNS, Wi-Fi, egress, and target services from the endpoint's perspective.
- **Outbound only**: the Agent receives monitoring configuration and uploads results over a persistent outbound connection; it never listens on a port.
- **Survives disconnections**: telemetry is written to a local WAL and uploaded after connectivity returns.
- **Centrally managed**: monitoring targets are pushed from the console, so probe jobs do not need to be edited device by device.
- **Explicit permission boundaries**: a local policy limits what the Agent may collect, while a target-access policy limits where probes may connect.
- **Cross-platform**: Windows, Linux, and macOS are supported, with native-service and Docker deployment options.
- **Bandwidth efficient**: telemetry is batched and sent as Protobuf by default, with JSON available for troubleshooting.

## What It Can Monitor

- ICMP latency, packet loss, jitter, and path diagnostics
- DNS resolution, TCP connection time, TLS handshakes, and HTTP availability
- Default gateways, network interfaces, routes, neighbors, and NAT behavior
- Wi-Fi connection state, signal strength, and link rates, where supported by the OS
- CPU, memory, disks, load, network throughput, temperature, and other host metrics
- Process and connection snapshots, including incident-time diagnostics
- Monitors routed through SOCKS5, HTTP CONNECT, or WireGuard egress

Available capabilities depend on the operating system, the local permission policy, and process privileges. The Agent reports supported, granted, and effective capabilities to the console instead of substituting synthetic zero values for data it cannot collect.

## Installation, Configuration, and Operations

Agent installation and operational guidance is maintained in the NetTact documentation:

- [Deploy NetTact Server](https://nettact.org/en/deploy): one-command deployment, first login, remote Agents, upgrades, backups, HTTPS, and troubleshooting.
- [Agent configuration](https://nettact.org/en/agent-config): installation on Windows, Linux, macOS, and Docker; enrollment tokens; YAML and environment variables; updates and troubleshooting.
- [Permission reference](https://nettact.org/en/permissions): permission presets, platform support, probe target-access controls, and every permission's meaning.

An annotated configuration template is available at [`agent.example.yaml`](./agent.example.yaml). Treat the user documentation and `nettact-agent --help` as the source of truth for installation commands, configuration, and operational procedures; they are intentionally not duplicated here.

## Building from Source

The project requires Go 1.25. Keep the NetTact Go modules in one workspace so the root `go.work` can resolve local dependencies:

```bash
go build ./...
go test ./...
go build -o nettact-agent ./cmd/nettact-agent
```

The runtime can also be imported as the [`agentrt`](./agentrt) Go package. The standalone Agent and NetTact Desktop use the same collection runtime.

## License

[Apache License 2.0](./LICENSE)
