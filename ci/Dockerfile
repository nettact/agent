# syntax=docker/dockerfile:1
#
# nettact-agent — the monitoring agent. A pure outbound client: it never listens on
# any port and runs as a non-root user.
#
# Capabilities: the Linux build implements ICMP probing, gateway probing and
# traceroute, which need a raw ICMP socket. The binary deliberately carries NO
# file capability, for two measured reasons:
#
#   * `setcap cap_net_raw+ep` makes execve() FAIL with EPERM whenever NET_RAW is
#     outside the container's bounding set, so `--cap-drop ALL` (a common
#     hardening default, and the k8s `capabilities: drop: [ALL]` idiom) would stop
#     the agent from starting at all instead of degrading gracefully.
#   * Docker's DEFAULT bounding set already contains NET_RAW, so a file
#     capability would silently hand raw sockets to every container, including
#     ones deliberately run in the isolated --container-view mode.
#
# Raw-socket access is therefore granted explicitly at run time instead: run the
# container as root (agent/install.sh --docker does this for its host view, where
# the container already shares the host's network and PID namespaces). Without it
# the agent still runs and simply reports ICMP as unsupported.
#
# Host visibility: by default a container sees its OWN network and processes. To
# monitor the machine, run with --network host --pid host and point HOST_PROC /
# HOST_SYS at bind-mounted host copies; agent/install.sh --docker does this.
#
# Build context: an assembled workspace directory with protocol/ and agent/ as
# siblings (the release workflow checks out protocol's default branch and records
# the resolved commit in nettact-agent-dependencies.json):
#   docker build -f agent/ci/Dockerfile --build-arg VERSION=v0.4.0 <workspace-dir>
# An isolated single-repo build fails on the v0.0.0 placeholder pseudo-versions.

# ---- Stage 1: cross-compile the static agent binary ------------------------
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
WORKDIR /src
COPY protocol/ protocol/
COPY agent/    agent/
# Trimmed workspace: mirror the local go.work's *versioned* replace so the placeholder
# require of github.com/nettact/protocol resolves to the local dir (`use` alone does
# not override the invalid v0.0.0 version). agent + protocol go.sum cover the build.
RUN go work init ./protocol ./agent \
 && go work edit -replace github.com/nettact/protocol@v0.0.0-00010101000000-000000000000=./protocol
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags "-s -w -X github.com/nettact/agent/agentrt.Version=${VERSION}" \
      -o /out/nettact-agent ./agent/cmd/nettact-agent

# ---- Stage 2: minimal runtime ----------------------------------------------
FROM alpine:3.22
# ca-certificates so the agent can dial https(s)/wss servers.
RUN apk add --no-cache ca-certificates \
 && addgroup -S nettact && adduser -S -G nettact nettact \
 && mkdir -p /agent-data && chown nettact:nettact /agent-data
COPY --from=build /out/nettact-agent /usr/local/bin/nettact-agent
USER nettact
# Persist identity (agent.key), server credential (agent.json), and the WAL outbox here.
ENV NETTACT_AGENT_DATA_DIR=/agent-data
WORKDIR /agent-data
VOLUME ["/agent-data"]
# No EXPOSE: outbound-only. All config is via NETTACT_AGENT_* env (see agent --help).
ENTRYPOINT ["nettact-agent"]

ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="nettact-agent" \
      org.opencontainers.image.description="NetTact monitoring agent (outbound-only push telemetry client)" \
      org.opencontainers.image.source="https://github.com/nettact/agent" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0"
