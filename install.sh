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
CONTAINER_VIEW=false
PERMISSIONS=""
TOKEN_FILE=""

usage() {
  cat <<'EOF'
NetTact Agent installer

Usage:
  install.sh --server-url <url> --token <one-time-token> [options]
  install.sh --docker --server-url <url> --token <one-time-token> [options]
  install.sh --update-only

The same script installs a native systemd service on Linux, a launchd daemon on
macOS, or a persistent container when --docker is selected. A full install
REPLACES any previous installation — the previous Agent identity is wiped so
the machine re-enrolls with the token given here. --update-only upgrades the
binary in place and keeps the identity.

Options:
  --auto-update        Install a daily native update timer, or an Agent-scoped
                       Docker image updater.
  --permissions <list> Comma-separated local permission policy, or the literal
                       "none". This REPLACES the Agent's built-in default set
                       rather than adding to it; omit it to keep the default.
                       Wildcards are not accepted. The NetTact console's Agent
                       page generates a ready-made value for you.
  --container-view     Docker only: monitor the CONTAINER instead of the host.
                       By default a Docker install monitors the Docker host —
                       host network and PID namespaces, the host's /proc and
                       /sys, and NET_RAW for ICMP — because that is the machine
                       an operator means to watch. This flag opts out.
EOF
}

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '==> %s\n' "$*"; }

# Positive install verification: run the given check command (a test for the
# Agent's persisted agent.json, which appears the moment enrollment succeeds)
# until it passes or the deadline expires. That file is proof the server was
# reachable and the token accepted. Merely "the service/container is running" is
# NOT success — on an unreachable server the Agent exits after its 30s enroll
# timeout and the service manager quietly restarts it forever, which is exactly
# the install that used to be reported as successful. The window outlasts one
# full enroll attempt plus a restart.
wait_enrolled() {
  deadline=$(( $(date +%s) + 75 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    "$@" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --server-url) SERVER_URL="${2:?--server-url needs a value}"; shift 2 ;;
    --token) TOKEN="${2:?--token needs a value}"; shift 2 ;;
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --auto-update) AUTO_UPDATE=true; shift ;;
    --update-only) UPDATE_ONLY=true; shift ;;
    --docker) DOCKER_MODE=true; shift ;;
    --container-view) CONTAINER_VIEW=true; shift ;;
    --permissions) PERMISSIONS="${2:?--permissions needs a value}"; shift 2 ;;
    --token-file) TOKEN_FILE="${2:?--token-file needs a value}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

# Normalize and validate the permission policy before touching anything: the
# Agent rejects an unsatisfiable policy at startup, and finding that out after the
# service is installed is a worse experience than failing here. Whitespace is
# stripped rather than rejected so a value pasted out of the console or a wrapped
# shell line still works.
if [ -n "$PERMISSIONS" ]; then
  PERMISSIONS="$(printf '%s' "$PERMISSIONS" | tr -d '[:space:]')"
  case "$PERMISSIONS" in
    "") die "--permissions needs a value (use \"none\" for an empty grant)" ;;
    *'*'*|all|ALL) die "--permissions does not accept wildcards; list explicit permissions or \"none\"" ;;
  esac
  # A value of only separators (",", ",,,") would emit a `permissions:` key with
  # no children, which the Agent reads as "not configured" and answers with the
  # full built-in DEFAULT grant — the opposite of the restriction that was asked
  # for, and silently. Require at least one real entry.
  if [ "$PERMISSIONS" != none ] && [ -z "$(printf '%s' "$PERMISSIONS" | tr -d ',')" ]; then
    die "--permissions lists no permissions; pass explicit ids or \"none\" for an empty grant"
  fi
fi

if $DOCKER_MODE; then
  command -v docker >/dev/null 2>&1 || die "docker is required for --docker"
  docker info >/dev/null 2>&1 || die "cannot connect to the Docker daemon"
fi
$CONTAINER_VIEW && ! $DOCKER_MODE && die "--container-view requires --docker"
[ -n "$TOKEN_FILE" ] && ! $DOCKER_MODE && die "--token-file is only supported with --docker"

$UPDATE_ONLY || {
  [ -n "$SERVER_URL" ] || die "--server-url is required"
  if [ -z "$TOKEN" ]; then
    if $DOCKER_MODE && [ -n "$TOKEN_FILE" ]; then
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
  # Tear the previous installation down updater-FIRST: a leftover Watchtower
  # could restart the new container mid-enrollment (burning the one-time token
  # after the server marked it used but before the credential was saved), and
  # would survive a failed install holding the Docker socket. It is re-created
  # below only when --auto-update is on THIS command line and the install
  # verified.
  docker rm -f nettact-agent-updater >/dev/null 2>&1 || true
  docker rm -f nettact-agent >/dev/null 2>&1 || true
  # A full install replaces the previous one: the identity volume is removed so
  # the Agent re-enrolls with the token given HERE. Resuming the old identity
  # would silently ignore that token, and a stale credential (agent deleted in
  # the console, server moved) breaks startup in ways that look like network
  # failures. The wipe is also what makes agent.json a positive success signal.
  docker volume rm nettact-agent-data >/dev/null 2>&1 || true
  ! docker volume inspect nettact-agent-data >/dev/null 2>&1 || \
    die "could not remove the previous identity volume nettact-agent-data (still in use by another container?); remove it and re-run this command"
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
  [ -n "$PERMISSIONS" ] && RUN_ARGS+=(-e "NETTACT_AGENT_PERMISSIONS=$PERMISSIONS")

  # Host view (the default): share the host's network and PID namespaces and
  # expose its /proc and /sys, so the Agent reports the MACHINE rather than the
  # container it happens to run in. HOST_PROC/HOST_SYS redirect both the metric
  # collector and the Agent's own route/resolver reads to the same mounts, so a
  # host CPU figure can never sit next to a container's default gateway.
  #
  # --user 0:0 plus NET_RAW is what buys PATH DIAGNOSTICS specifically. ICMP
  # probing and gateway probing do not need it: they run over an unprivileged
  # ping socket wherever net.ipv4.ping_group_range allows, which is the Docker
  # default — measured working in a plain non-root container. Traceroute is
  # different because it must RECEIVE intermediate Time-Exceeded replies, and
  # only a raw socket delivers those. The image carries no file capability on
  # purpose (see ci/Dockerfile), so a non-root process has an empty permitted set
  # no matter what is in the bounding set, which is why this is root rather than
  # --cap-add alone. Root is a small addition to a container that already shares
  # the host's network and PID namespaces; --container-view keeps the hardened
  # non-root default and still gets ICMP probing.
  #
  # Two individual files, not the whole /etc: os-release is what identifies the
  # monitored machine (without it the Agent registers the CONTAINER IMAGE's
  # distribution — "alpine" for an Ubuntu host), and resolv.conf is the resolver
  # list it reports. Bind-mounting all of /etc would hand the container the host's
  # shadow file and keys for two values.
  #
  # "Host" means the Docker DAEMON's host. On Docker Desktop that is the Linux
  # VM, not Windows or macOS — there is no way for a Linux container to observe
  # the outer OS, and the VM is the closest true answer.
  if ! $CONTAINER_VIEW; then
    DOCKER_OS="$(docker info --format '{{.OSType}}' 2>/dev/null || echo unknown)"
    if [ "$DOCKER_OS" != linux ]; then
      CONTAINER_VIEW=true
      log "Docker host is not Linux ($DOCKER_OS); monitoring the container itself"
    elif [ ! -d /proc ] || [ ! -d /sys ]; then
      CONTAINER_VIEW=true
      log "host /proc or /sys is unavailable; monitoring the container itself"
    fi
  fi
  if $CONTAINER_VIEW; then
    log "container view: this Agent reports the container's own network and processes"
    # The host view below runs the container as root, which can read any token
    # file; container view keeps the image's non-root user. A bind-mounted file
    # arrives with the HOST's owner and mode, so a secret written 0600 by root is
    # unreadable there and the Agent would fail enrollment 30 seconds from now
    # with nothing but "permission denied" in a log the operator has to go find.
    # Ask the image itself rather than guessing its uid.
    if [ -n "${ABS_TOKEN_FILE:-}" ] && ! docker run --rm --entrypoint cat \
        -v "$ABS_TOKEN_FILE:/run/secrets/agent_enroll_token:ro" "$IMG" \
        /run/secrets/agent_enroll_token >/dev/null 2>&1; then
      die "the Agent runs as a non-root user in container view and cannot read $ABS_TOKEN_FILE.
  Make the FILE readable and keep its DIRECTORY private:
    chmod 644 $ABS_TOKEN_FILE && chmod 700 $(dirname "$ABS_TOKEN_FILE")
  or pass the token inline with --token instead of --token-file."
    fi
  else
    log "host view: this Agent reports the Docker daemon host's network, processes and metrics"
    log "  (disk metrics still describe the container's filesystem — see the permissions docs)"
    RUN_ARGS+=(--network host --pid host --cap-add NET_RAW --user 0:0
      -v /proc:/host/proc:ro -v /sys:/host/sys:ro
      -e HOST_PROC=/host/proc -e HOST_SYS=/host/sys -e HOST_ETC=/host/etc)
    for f in os-release resolv.conf; do
      [ -r "/etc/$f" ] && RUN_ARGS+=(-v "/etc/$f:/host/etc/$f:ro")
    done
  fi
  docker run "${RUN_ARGS[@]}" "$IMG" >/dev/null

  log "verifying server connectivity and enrolling"
  if ! wait_enrolled docker exec nettact-agent test -f /agent-data/agent.json; then
    docker logs --tail 30 nettact-agent >&2 || true
    docker rm -f nettact-agent >/dev/null 2>&1 || true
    die "INSTALL FAILED: the Agent could not enroll with $SERVER_URL (see its log above). The container was removed; fix the problem, generate a fresh token in the console, and re-run this command."
  fi
  # Enrollment succeeded, but the restart policy would also mask an Agent that
  # crashes right after it: the credential survives restarts, so agent.json
  # alone cannot vouch for a stable process. Require the SAME container
  # instance to still be up after a short dwell — a crash loop shows up as a
  # changed StartedAt or Running=false.
  STARTED_AT="$(docker inspect -f '{{.State.StartedAt}}' nettact-agent 2>/dev/null)"
  sleep 3
  if [ "$(docker inspect -f '{{.State.Running}}' nettact-agent 2>/dev/null)" != true ] || \
     [ "$(docker inspect -f '{{.State.StartedAt}}' nettact-agent 2>/dev/null)" != "$STARTED_AT" ]; then
    docker logs --tail 30 nettact-agent >&2 || true
    docker rm -f nettact-agent >/dev/null 2>&1 || true
    die "INSTALL FAILED: the Agent enrolled but did not stay running (see its log above). The container was removed; fix the problem, generate a fresh token in the console, and re-run this command."
  fi
  if $AUTO_UPDATE; then
    log "enabling daily automatic Agent image updates"
    docker run -d --name nettact-agent-updater --restart unless-stopped -v /var/run/docker.sock:/var/run/docker.sock containrrr/watchtower:latest --cleanup --interval 86400 nettact-agent >/dev/null
  fi
  log "SUCCESS: Agent enrolled and running (logs: docker logs -f nettact-agent)"
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

# Tear the previous installation down BEFORE touching its state, updater
# FIRST: a leftover update timer/daemon runs --update-only, which restarts the
# Agent — mid-enrollment that can burn the one-time token (after the server
# marked it used but before the credential was saved), and after a failed
# install it would resurrect a disabled service. It is re-created below only
# when --auto-update is on THIS command line. Then the Agent itself, which
# would otherwise write into the data dir between the wipe and the restart.
if [ "$OS" = linux ]; then
  systemctl disable --now nettact-agent-update.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/nettact-agent-update.timer /etc/systemd/system/nettact-agent-update.service
  systemctl stop nettact-agent.service >/dev/null 2>&1 || true
else
  launchctl bootout system/org.nettact.agent.update >/dev/null 2>&1 || true
  rm -f /Library/LaunchDaemons/org.nettact.agent.update.plist
  launchctl bootout system/org.nettact.agent >/dev/null 2>&1 || true
fi
rm -rf /usr/local/lib/nettact-agent

# A full install replaces the previous one: the data dir (identity + queued
# telemetry) is wiped so the Agent re-enrolls with the token given HERE — see
# the Docker section for why resuming the old identity would be wrong.
# --update-only is the path that keeps identity.
rm -rf "$DATA_DIR"
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
# Emit the permission policy as a YAML block list, or the literal `none` scalar
# for an empty grant. Omitting the key entirely (no --permissions) leaves the
# Agent on its built-in default set — writing an empty list would instead mean
# "grant nothing", which is a very different install.
yaml_permissions() {
  case "$PERMISSIONS" in
    "") return ;;
    none) printf 'permissions: none\n'; return ;;
  esac
  printf 'permissions:\n'
  # The trailing newline matters: without it `read` fails on the final field and
  # the last permission is silently dropped from the installed policy.
  printf '%s\n' "$PERMISSIONS" | tr ',' '\n' | while IFS= read -r perm; do
    [ -n "$perm" ] || continue
    printf '  - '; yaml_quote "$perm"; printf '\n'
  done
}
{
  printf 'server_url: '; yaml_quote "$SERVER_URL"; printf '\n'
  printf 'data_dir: '; yaml_quote "$DATA_DIR"; printf '\n'
  printf 'enroll_token_file: '; yaml_quote "$TOKEN_FILE"; printf '\n'
  yaml_permissions
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
  # enable + restart, NOT enable --now + restart: two starts in a row can kill
  # the first instance mid-enrollment — after the server marked the one-time
  # token used but before the credential was saved — burning the token.
  systemctl enable nettact-agent.service
  systemctl restart nettact-agent.service
  log "verifying server connectivity and enrolling"
  if ! wait_enrolled test -f "$DATA_DIR/agent.json"; then
    journalctl -u nettact-agent.service -n 30 --no-pager >&2 || true
    systemctl disable --now nettact-agent.service >/dev/null 2>&1 || true
    die "INSTALL FAILED: the Agent could not enroll with $SERVER_URL (see its log above). Nothing was left running; fix the problem, generate a fresh token in the console, and re-run this command."
  fi
  # Enrollment succeeded, but Restart=always would also mask an Agent that
  # crashes right after it: the credential survives restarts, so agent.json
  # alone cannot vouch for a stable process. Require the SAME service instance
  # to still be active after a short dwell — a crash loop shows up as inactive
  # (auto-restart pending) or a changed activation timestamp.
  STARTED="$(systemctl show -p ActiveEnterTimestampMonotonic nettact-agent.service 2>/dev/null)"
  sleep 3
  if ! systemctl is-active --quiet nettact-agent.service || \
     [ "$(systemctl show -p ActiveEnterTimestampMonotonic nettact-agent.service 2>/dev/null)" != "$STARTED" ]; then
    journalctl -u nettact-agent.service -n 30 --no-pager >&2 || true
    systemctl disable --now nettact-agent.service >/dev/null 2>&1 || true
    die "INSTALL FAILED: the Agent enrolled but did not stay running (see its log above). Nothing was left running; fix the problem, generate a fresh token in the console, and re-run this command."
  fi
  log "SUCCESS: Agent enrolled and running (logs: journalctl -u nettact-agent -f)"
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
  # bootstrap starts the daemon (RunAtLoad); a kickstart -k on top would be a
  # second start that can kill the first mid-enrollment and burn the token.
  launchctl bootstrap system "$PLIST"
  log "verifying server connectivity and enrolling"
  if ! wait_enrolled test -f "$DATA_DIR/agent.json"; then
    tail -n 30 /var/log/nettact-agent.log >&2 2>/dev/null || true
    launchctl bootout system/org.nettact.agent >/dev/null 2>&1 || true
    rm -f "$PLIST"
    die "INSTALL FAILED: the Agent could not enroll with $SERVER_URL (see its log above). Nothing was left running; fix the problem, generate a fresh token in the console, and re-run this command."
  fi
  # Enrollment succeeded, but KeepAlive would also mask an Agent that crashes
  # right after it: the credential survives restarts, so agent.json alone
  # cannot vouch for a stable process. Require the SAME process to still be up
  # after a short dwell — a crash loop shows up as a missing or changed PID.
  AGENT_PID="$(pgrep -x nettact-agent || true)"
  sleep 3
  if [ -z "$AGENT_PID" ] || [ "$(pgrep -x nettact-agent || true)" != "$AGENT_PID" ]; then
    tail -n 30 /var/log/nettact-agent.log >&2 2>/dev/null || true
    launchctl bootout system/org.nettact.agent >/dev/null 2>&1 || true
    rm -f "$PLIST"
    die "INSTALL FAILED: the Agent enrolled but did not stay running (see its log above). Nothing was left running; fix the problem, generate a fresh token in the console, and re-run this command."
  fi
  log "SUCCESS: Agent enrolled and running (logs: tail -f /var/log/nettact-agent.log)"
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
