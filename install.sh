#!/usr/bin/env bash
# One-command NetTact Agent installer for Linux, macOS, and Docker.
set -euo pipefail

SERVER_URL="${NETTACT_AGENT_SERVER_URL:-}"
TOKEN="${NETTACT_AGENT_ENROLL_TOKEN:-}"
VERSION="latest"
DOWNLOAD_BASE="${NETTACT_AGENT_DOWNLOAD_BASE:-https://d.nettact.org/agent}"
AUTO_UPDATE=false
UPDATE_ONLY=false
DOCKER_MODE=false
HOST_NETWORK=false
TOKEN_FILE=""

usage() {
  cat <<'EOF'
NetTact Agent installer

Usage:
  install.sh --server-url <url> --token <one-time-token> [--auto-update]
  install.sh --docker --server-url <url> --token <one-time-token> [--auto-update]
  install.sh --update-only

The same script installs a native systemd service on Linux, a launchd daemon on
macOS, or a persistent container when --docker is selected. Re-running upgrades
the native binary and keeps the existing Agent identity. --auto-update installs
a daily native update timer or an Agent-scoped Docker image updater.
EOF
}

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '==> %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --server-url) SERVER_URL="${2:?--server-url needs a value}"; shift 2 ;;
    --token) TOKEN="${2:?--token needs a value}"; shift 2 ;;
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --auto-update) AUTO_UPDATE=true; shift ;;
    --update-only) UPDATE_ONLY=true; shift ;;
    --docker) DOCKER_MODE=true; shift ;;
    --host-network) HOST_NETWORK=true; shift ;;
    --token-file) TOKEN_FILE="${2:?--token-file needs a value}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

if $DOCKER_MODE; then
  command -v docker >/dev/null 2>&1 || die "docker is required for --docker"
  docker info >/dev/null 2>&1 || die "cannot connect to the Docker daemon"
fi
$HOST_NETWORK && ! $DOCKER_MODE && die "--host-network requires --docker"
[ -n "$TOKEN_FILE" ] && ! $DOCKER_MODE && die "--token-file is only supported with --docker"

$UPDATE_ONLY || {
  [ -n "$SERVER_URL" ] || die "--server-url is required"
  if [ -z "$TOKEN" ]; then
    if $DOCKER_MODE && [ -n "$TOKEN_FILE" ]; then
      :
    elif $DOCKER_MODE && docker volume inspect nettact-agent-data >/dev/null 2>&1; then
      :
    else
      die "--token is required (Docker also accepts --token-file)"
    fi
  fi
  case "$SERVER_URL$TOKEN" in *'
'*) die "server URL and token must each be a single line" ;; esac
}
$AUTO_UPDATE && [ "$VERSION" != latest ] && die "--auto-update cannot be combined with a pinned --version"
$DOCKER_MODE && $UPDATE_ONLY && die "--update-only is for native installations; Docker updates are handled automatically"

if $DOCKER_MODE; then
  [ -n "$TOKEN_FILE" ] && [ ! -r "$TOKEN_FILE" ] && die "token file not readable: $TOKEN_FILE"

  IMG="ghcr.io/nettact/nettact-agent:${VERSION:-latest}"
  log "starting Agent container from $IMG"
  docker rm -f nettact-agent >/dev/null 2>&1 || true
  RUN_ARGS=(-d --name nettact-agent --restart unless-stopped
    -e "NETTACT_AGENT_SERVER_URL=$SERVER_URL"
    -e NETTACT_AGENT_DATA_DIR=/agent-data
    -v nettact-agent-data:/agent-data)
  if [ -n "$TOKEN_FILE" ]; then
    ABS_TOKEN_FILE="$(cd "$(dirname "$TOKEN_FILE")" && pwd)/$(basename "$TOKEN_FILE")"
    RUN_ARGS+=(-v "$ABS_TOKEN_FILE:/run/secrets/agent_enroll_token:ro"
      -e NETTACT_AGENT_ENROLL_TOKEN_FILE=/run/secrets/agent_enroll_token)
  elif [ -n "$TOKEN" ]; then
    RUN_ARGS+=(-e "NETTACT_AGENT_ENROLL_TOKEN=$TOKEN")
  fi
  $HOST_NETWORK && RUN_ARGS+=(--network host)
  docker run "${RUN_ARGS[@]}" "$IMG" >/dev/null

  sleep 2
  [ "$(docker inspect -f '{{.State.Running}}' nettact-agent 2>/dev/null)" = true ] || {
    docker logs --tail 30 nettact-agent >&2 || true
    die "Agent container failed to stay running"
  }
  if $AUTO_UPDATE; then
    log "enabling daily automatic Agent image updates"
    docker rm -f nettact-agent-updater >/dev/null 2>&1 || true
    docker run -d --name nettact-agent-updater --restart unless-stopped -v /var/run/docker.sock:/var/run/docker.sock containrrr/watchtower:latest --cleanup --interval 86400 nettact-agent >/dev/null
  fi
  log "Agent installed and running (logs: docker logs -f nettact-agent)"
  exit 0
fi

[ "$(id -u)" -eq 0 ] || die "run native installation as root (for example, pipe it to 'sudo bash')"

case "$(uname -s)" in
  Linux) OS=linux ;;
  Darwin) OS=darwin ;;
  *) die "unsupported operating system: $(uname -s)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) die "unsupported CPU architecture: $(uname -m)" ;;
esac
command -v curl >/dev/null 2>&1 || die "curl is required"

if [ "$VERSION" = latest ]; then
  URL="$DOWNLOAD_BASE/nettact-agent-$OS-$ARCH"
else
  URL="$DOWNLOAD_BASE/$VERSION/nettact-agent-$OS-$ARCH"
fi

BIN=/usr/local/bin/nettact-agent
if [ "$OS" = linux ]; then
  CONFIG_DIR=/etc/nettact
  DATA_DIR=/var/lib/nettact-agent
else
  CONFIG_DIR="/Library/Application Support/NetTact"
  DATA_DIR="$CONFIG_DIR/agent-data"
fi
CONFIG_FILE="$CONFIG_DIR/agent.yaml"
TOKEN_FILE="$CONFIG_DIR/enroll.token"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
log "downloading NetTact Agent for $OS/$ARCH"
curl -fsSL "$URL" -o "$tmp"

if $UPDATE_ONLY; then
  [ -x "$BIN" ] || die "Agent is not installed at $BIN"
  if cmp -s "$tmp" "$BIN"; then
    log "Agent is already up to date"
    exit 0
  fi
  install -m 0755 "$tmp" "$BIN"
  if [ "$OS" = linux ]; then
    systemctl restart nettact-agent.service
  else
    launchctl kickstart -k system/org.nettact.agent
  fi
  log "Agent updated and restarted"
  exit 0
fi

install -m 0755 "$tmp" "$BIN"
mkdir -p "$CONFIG_DIR" "$DATA_DIR"
chmod 0700 "$CONFIG_DIR" "$DATA_DIR"
printf '%s' "$TOKEN" > "$TOKEN_FILE"
chmod 0600 "$TOKEN_FILE"

# JSON quoted strings are valid YAML scalars and safely preserve URLs/paths.
yaml_quote() {
  printf '%s' "$1" | awk 'BEGIN { ORS=""; print "\"" } {
    if (NR > 1) print "\\n"
    gsub(/\\/, "\\\\")
    gsub(/"/, "\\\"")
    printf "%s", $0
  } END { print "\"" }'
}
{
  printf 'server_url: '; yaml_quote "$SERVER_URL"; printf '\n'
  printf 'data_dir: '; yaml_quote "$DATA_DIR"; printf '\n'
  printf 'enroll_token_file: '; yaml_quote "$TOKEN_FILE"; printf '\n'
} > "$CONFIG_FILE"
chmod 0600 "$CONFIG_FILE"

if [ "$OS" = linux ]; then
  command -v systemctl >/dev/null 2>&1 || die "systemd is required for native Linux installation; use the Docker option on other init systems"
  cat > /etc/systemd/system/nettact-agent.service <<EOF
[Unit]
Description=NetTact monitoring agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN --config $CONFIG_FILE
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now nettact-agent.service
  systemctl restart nettact-agent.service
  sleep 2
  systemctl is-active --quiet nettact-agent.service || {
    journalctl -u nettact-agent.service -n 30 --no-pager >&2 || true
    die "Agent service failed to start"
  }
  log "Agent installed and running (logs: journalctl -u nettact-agent -f)"
else
  PLIST=/Library/LaunchDaemons/org.nettact.agent.plist
  launchctl bootout system/org.nettact.agent >/dev/null 2>&1 || true
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>org.nettact.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BIN</string>
    <string>--config</string>
    <string>$CONFIG_FILE</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/nettact-agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/nettact-agent.log</string>
</dict>
</plist>
EOF
  chmod 0644 "$PLIST"
  launchctl bootstrap system "$PLIST"
  launchctl kickstart -k system/org.nettact.agent
  sleep 2
  launchctl print system/org.nettact.agent >/dev/null 2>&1 || die "Agent daemon failed to start"
  log "Agent installed and running (logs: tail -f /var/log/nettact-agent.log)"
fi

if $AUTO_UPDATE; then
  UPDATE_DIR=/usr/local/lib/nettact-agent
  UPDATE_SCRIPT=$UPDATE_DIR/install.sh
  mkdir -p "$UPDATE_DIR"
  curl -fsSL "$DOWNLOAD_BASE/install.sh" -o "$UPDATE_SCRIPT"
  chmod 0755 "$UPDATE_SCRIPT"
  if [ "$OS" = linux ]; then
    cat > /etc/systemd/system/nettact-agent-update.service <<EOF
[Unit]
Description=Update the NetTact monitoring agent
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$UPDATE_SCRIPT --update-only
EOF
    cat > /etc/systemd/system/nettact-agent-update.timer <<'EOF'
[Unit]
Description=Check daily for NetTact Agent updates

[Timer]
OnBootSec=15min
OnUnitActiveSec=24h
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now nettact-agent-update.timer
  else
    UPDATE_PLIST=/Library/LaunchDaemons/org.nettact.agent.update.plist
    launchctl bootout system/org.nettact.agent.update >/dev/null 2>&1 || true
    cat > "$UPDATE_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>org.nettact.agent.update</string>
  <key>ProgramArguments</key>
  <array>
    <string>$UPDATE_SCRIPT</string>
    <string>--update-only</string>
  </array>
  <key>StartInterval</key><integer>86400</integer>
  <key>StandardOutPath</key><string>/var/log/nettact-agent-update.log</string>
  <key>StandardErrorPath</key><string>/var/log/nettact-agent-update.log</string>
</dict>
</plist>
EOF
    chmod 0644 "$UPDATE_PLIST"
    launchctl bootstrap system "$UPDATE_PLIST"
  fi
  log "Daily automatic updates enabled"
fi

log "The Agent should appear in the NetTact console within seconds."
