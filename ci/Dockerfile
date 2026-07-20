# syntax=docker/dockerfile:1
#
# nettact-agent — the monitoring agent. A pure outbound client: it never listens on
# any port, and on Linux needs no NET_RAW/privileged (ICMP probing is Windows-only in
# this build), so it runs as a non-root user with no added capabilities.
#
# Build context: an assembled workspace directory with protocol/ and agent/ as
# siblings (the release workflow checks out protocol at ci/deps.env's PROTOCOL_SHA):
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
