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
# Docker only: where the deployment's compose file, .env and enrollment token
# live. A NATIVE install is unaffected — it stays on the platform's own paths
# (/usr/local/bin, /etc/nettact, /var/lib/nettact-agent), because those are what
# systemd, launchd and every uninstall instruction already refer to.
INSTALL_DIR="${NETTACT_AGENT_INSTALL_DIR:-}"

usage() {
  cat <<'EOF'
NetTact Agent installer

Usage:
  install.sh --server-url <url> --token <one-time-token> [options]
  install.sh --docker --server-url <url> --token <one-time-token> [options]
  install.sh --update-only

The same script installs a native systemd service on Linux, a launchd daemon on
macOS, or a docker compose deployment when --docker is selected. A full install
REPLACES any previous installation — the previous Agent identity is wiped so
the machine re-enrolls with the token given here. --update-only upgrades the
binary in place and keeps the identity.

With --docker the deployment is written to ~/nettact-agent (compose file, .env
and the enrollment token) and started from there, so it can be managed with
ordinary compose commands afterwards:
  cd ~/nettact-agent && docker compose ps | logs -f | down

Options:
  --auto-update        Install a daily native updater, or (Linux Docker only)
                       a host systemd timer that updates the Agent container.
  --permissions <list> Comma-separated local permission policy, or the literal
                       "none". This REPLACES the Agent's built-in default set
                       rather than adding to it; omit it to keep the default.
                       Wildcards are not accepted. The NetTact console's Agent
                       page generates a ready-made value for you.
  --container-view     Docker only: monitor the CONTAINER instead of the host.
                       By default a Docker install monitors the Docker host —
                       host network and PID namespaces, the host's /proc and
                       /sys, and root plus NET_RAW for path diagnostics —
                       because that is the machine an operator means to watch.
                       This flag opts out: the container stays non-root and
                       keeps ICMP and gateway probing over a ping socket, but
                       path diagnostics are unavailable there.

Environment:
  NETTACT_AGENT_INSTALL_DIR   --docker: where to write the deployment
                              (default: ~/nettact-agent)
EOF
}

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '==> %s\n' "$*"; }

as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    die "installing the systemd update timer needs root; install sudo or run this installer as root with NETTACT_AGENT_INSTALL_DIR set"
  fi
}

# JSON quoted strings are valid YAML scalars and safely preserve URLs/paths.
yaml_quote() {
  printf '%s' "$1" | awk 'BEGIN { ORS=""; print "\"" } {
    if (NR > 1) print "\\n"
    gsub(/\\/, "\\\\")
    gsub(/"/, "\\\"")
    printf "%s", $0
  } END { print "\"" }'
}

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
  DOCKER_BIN="$(command -v docker 2>/dev/null || true)"
  [ -n "$DOCKER_BIN" ] || die "docker is required for --docker"
  case "$DOCKER_BIN" in /*) ;; *) die "cannot resolve docker to an absolute executable path: $DOCKER_BIN" ;; esac
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
  # The console shows this command with a placeholder token until one is
  # generated, and it is copied and run in that state often enough to be worth
  # naming: the enrollment would answer 401 several steps from here, after the
  # download, the service install and the identity wipe, and the machine would
  # be left with an agent that enrolls nowhere. Say what actually went wrong,
  # before anything on this host is touched.
  case "$TOKEN" in
    '<enrollment-token>')
      die "the --token value is still the console's placeholder, so no enrollment token was ever generated.
  In the NetTact console open Agents -> Add agent, click \"Generate token\", then copy this command again from that page." ;;
  esac
  case "$SERVER_URL$TOKEN" in *'
'*) die "server URL and token must each be a single line" ;; esac
}
$AUTO_UPDATE && [ "$VERSION" != latest ] && die "--auto-update cannot be combined with a pinned --version"
$DOCKER_MODE && $UPDATE_ONLY && die "--update-only is for native installations; Docker updates are handled automatically"

if $DOCKER_MODE; then
  [ -n "$TOKEN_FILE" ] && [ ! -r "$TOKEN_FILE" ] && die "token file not readable: $TOKEN_FILE"
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required for --docker ('docker compose version' failed).
  On Debian/Ubuntu: apt install docker-compose-plugin — see https://docs.docker.com/compose/install/"

  # ---------- where the deployment lives ------------------------------------------
  # A `docker run` install left nothing on disk: reproducing, inspecting or
  # changing it meant reconstructing a fifteen-flag command line out of `docker
  # inspect`. The deployment is written out as a compose project instead — one
  # directory that IS the container's definition, plus the ordinary compose verbs
  # to manage it. Fixed location, not the current directory, because it outlives
  # the shell that created it.
  if [ -z "$INSTALL_DIR" ]; then
    [ -n "${HOME:-}" ] || die "HOME is not set — pass NETTACT_AGENT_INSTALL_DIR=<dir> to choose where to install"
    INSTALL_DIR="$HOME/nettact-agent"
  fi
  mkdir -p "$INSTALL_DIR" || die "cannot create the install directory $INSTALL_DIR"
  INSTALL_DIR="$(cd "$INSTALL_DIR" && pwd -P)"
  # The enrollment token lives in here, so the DIRECTORY is what keeps it private:
  # the token file itself must stay other-readable (see below).
  chmod 700 "$INSTALL_DIR" 2>/dev/null || true

  IMG_REPO="${NETTACT_AGENT_IMAGE:-ghcr.io/nettact/nettact-agent}"
  IMG="$IMG_REPO:${VERSION:-latest}"

  # compose <args…> — always address the resolved deployment files by absolute
  # path, and never let the
  # invoking shell's own NETTACT_AGENT_* variables win over the .env we just
  # wrote. Compose resolves interpolation from the environment FIRST, so an
  # exported NETTACT_AGENT_SERVER_URL (the very variable this script accepts as a
  # default for --server-url) would otherwise silently deploy a different server
  # than the one requested on the command line.
  compose() {
    env -u NETTACT_AGENT_IMAGE -u NETTACT_AGENT_VERSION -u NETTACT_AGENT_SERVER_URL \
      "$DOCKER_BIN" compose --project-directory "$INSTALL_DIR" \
      --env-file "$INSTALL_DIR/.env" -f "$INSTALL_DIR/docker-compose.yml" "$@"
  }

  # write_compose <sysctls?> — regenerate docker-compose.yml. The host view and
  # container view are structurally different containers, which is why this is
  # generated rather than selected through an .env value.
  write_compose() {
    local want_sysctls="$1"
    {
      cat <<'YAML'
# NetTact Agent — generated by install.sh. Re-running the installer regenerates
# this file AND wipes the Agent's identity (it re-enrolls with a fresh token), so
# treat edits here as the way to change the deployment: adjust, then
#   docker compose up -d
#
# Knobs live in .env beside this file. The enrollment token is ./enroll.token,
# mounted read-only; it is only read on first run, when there is no credential in
# the data volume yet.
services:
  agent:
    image: ${NETTACT_AGENT_IMAGE:-ghcr.io/nettact/nettact-agent}:${NETTACT_AGENT_VERSION:-latest}
    container_name: nettact-agent
    restart: unless-stopped
    environment:
      NETTACT_AGENT_SERVER_URL: ${NETTACT_AGENT_SERVER_URL}
      NETTACT_AGENT_DATA_DIR: /agent-data
      NETTACT_AGENT_ENROLL_TOKEN_FILE: /run/secrets/agent_enroll_token
YAML
      # Only emitted when a policy was actually chosen: the Agent rejects an
      # empty NETTACT_AGENT_PERMISSIONS outright ("set but empty; use `none` or
      # unset it"), so an unconditional line would break every default install.
      if [ -n "$PERMISSIONS" ]; then
        printf '      NETTACT_AGENT_PERMISSIONS: '; yaml_quote "$PERMISSIONS"; printf '\n'
      fi
      if ! $CONTAINER_VIEW; then
        cat <<'YAML'
      HOST_PROC: /host/proc
      HOST_SYS: /host/sys
      HOST_ETC: /host/etc
YAML
      fi
      cat <<'YAML'
    volumes:
      - nettact-agent-data:/agent-data
      - ./enroll.token:/run/secrets/agent_enroll_token:ro
YAML
      if ! $CONTAINER_VIEW; then
        printf '      - /proc:/host/proc:ro\n      - /sys:/host/sys:ro\n'
        # Two individual files, not the whole /etc: os-release is what identifies
        # the monitored machine (without it the Agent registers the CONTAINER
        # IMAGE's distribution — "alpine" for an Ubuntu host), and resolv.conf is
        # the resolver list it reports. Bind-mounting all of /etc would hand the
        # container the host's shadow file and keys for two values.
        for f in os-release resolv.conf; do
          [ -r "/etc/$f" ] && printf '      - /etc/%s:/host/etc/%s:ro\n' "$f" "$f"
        done
        cat <<'YAML'
    network_mode: host
    pid: host
    user: "0:0"
    cap_add:
      - NET_RAW
YAML
      elif [ "$want_sysctls" = true ]; then
        cat <<'YAML'
    sysctls:
      # Opens the unprivileged ping socket for this container's own network
      # namespace. The kernel starts every namespace with "1 0" — an empty range,
      # no gid may ping — and dockerd does not change it, so without this line the
      # non-root Agent reports ICMP probing and gateway probing as unsupported.
      # It grants nothing on the host, and nothing beyond ICMP echo in here.
      net.ipv4.ping_group_range: "0 2147483647"
YAML
      fi
      cat <<'YAML'

volumes:
  # Holds agent.key, agent.json and the WAL outbox. Named explicitly so it does
  # not carry the compose project prefix: the identity survives the directory
  # being renamed, and `docker volume rm nettact-agent-data` means the same thing
  # in every set of instructions.
  nettact-agent-data:
    name: nettact-agent-data
YAML
    } > "$INSTALL_DIR/docker-compose.yml"
  }

  log "deploying the Agent into $INSTALL_DIR"
  DOCKER_UPDATE_SERVICE=/etc/systemd/system/nettact-agent-docker-update.service
  DOCKER_UPDATE_TIMER=/etc/systemd/system/nettact-agent-docker-update.timer
  DOCKER_UPDATE_SCRIPT=/usr/local/lib/nettact-agent-docker/update.sh
  if $AUTO_UPDATE && [ "$(uname -s)" != Linux ]; then
    die "--docker --auto-update requires a Linux host with systemd; automatic Docker updates are not installed on macOS"
  fi
  HAD_DOCKER_UPDATE_UNITS=false
  if [ -e "$DOCKER_UPDATE_SERVICE" ] || [ -e "$DOCKER_UPDATE_TIMER" ] || [ -e "$DOCKER_UPDATE_SCRIPT" ]; then
    HAD_DOCKER_UPDATE_UNITS=true
  fi
  if $AUTO_UPDATE || [ "$HAD_DOCKER_UPDATE_UNITS" = true ]; then
    command -v systemctl >/dev/null 2>&1 || die "systemd is required to install or remove the automatic Docker update timer"
    systemctl list-unit-files >/dev/null 2>&1 || die "systemd is not running; automatic Docker updates require a systemd host"
    as_root systemctl disable --now nettact-agent-docker-update.timer >/dev/null 2>&1 || true
    as_root systemctl stop nettact-agent-docker-update.service >/dev/null 2>&1 || true
    as_root rm -f "$DOCKER_UPDATE_SERVICE" "$DOCKER_UPDATE_TIMER" "$DOCKER_UPDATE_SCRIPT"
    as_root rmdir /usr/local/lib/nettact-agent-docker >/dev/null 2>&1 || true
    as_root systemctl daemon-reload
  fi
  # Tear the previous updater down FIRST: either the host timer or a legacy
  # Watchtower container could restart the Agent mid-enrollment and consume the
  # one-time token before its credential is saved.
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

  # The token as a FILE for both --token and --token-file. Not an environment
  # variable: compose would then need the value at every `up`, and a variable
  # that resolves to empty is a hard startup error in the Agent rather than a
  # no-op, so a later `docker compose up -d` typed by hand would break the
  # deployment. A stale token here is harmless — it is consulted only when the
  # data volume holds no credential.
  #
  # MODE 0644, not 0600: the container reads it through a bind mount, and in the
  # container view that process is uid 100, which cannot open a file owned by
  # whoever ran this installer. Confidentiality comes from the 0700 directory
  # above, which the bind mount does not have to traverse.
  if [ -n "$TOKEN_FILE" ]; then
    cp "$TOKEN_FILE" "$INSTALL_DIR/enroll.token" || die "cannot copy the token file into $INSTALL_DIR"
  else
    printf '%s' "$TOKEN" > "$INSTALL_DIR/enroll.token"
  fi
  chmod 644 "$INSTALL_DIR/enroll.token"

  # Host view (the default): share the host's network and PID namespaces and
  # expose its /proc and /sys, so the Agent reports the MACHINE rather than the
  # container it happens to run in. HOST_PROC/HOST_SYS redirect both the metric
  # collector and the Agent's own route/resolver reads to the same mounts, so a
  # host CPU figure can never sit next to a container's default gateway.
  #
  # user 0:0 plus NET_RAW is what buys PATH DIAGNOSTICS specifically, because
  # traceroute must RECEIVE the intermediate Time-Exceeded replies and only a raw
  # socket delivers those. The image carries no file capability on purpose (see
  # ci/Dockerfile), so a non-root process has an empty permitted set no matter
  # what is in the bounding set, which is why this is root rather than cap_add
  # alone. Root is a small addition to a container that already shares the host's
  # network and PID namespaces.
  #
  # ICMP probing and gateway probing need less — an unprivileged ping socket —
  # so the container view keeps the hardened non-root user and still gets both,
  # via the sysctl written into the compose file.
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
    log "  (ICMP and gateway probing via an unprivileged ping socket; no path diagnostics)"
  else
    log "host view: this Agent reports the Docker daemon host's network, processes and metrics"
    log "  (disk metrics still describe the container's filesystem — see the permissions docs)"
  fi

  # .env carries the values an operator would plausibly change; everything
  # structural is in the compose file. Written fresh on every full install, like
  # the compose file beside it.
  {
    printf '# NetTact Agent deployment — generated by install.sh.\n'
    printf '# Change a value and re-apply with: docker compose up -d\n'
    printf 'NETTACT_AGENT_IMAGE=%s\n' "$IMG_REPO"
    printf 'NETTACT_AGENT_VERSION=%s\n' "${VERSION:-latest}"
    printf 'NETTACT_AGENT_SERVER_URL=%s\n' "$SERVER_URL"
  } > "$INSTALL_DIR/.env"
  chmod 600 "$INSTALL_DIR/.env"

  # An explicit pull, so re-running the installer on a :latest deployment
  # actually upgrades: `compose up` only pulls a tag it does not already have
  # locally, which would leave a months-old "latest" running and call it a
  # successful reinstall.
  log "pulling $IMG"
  docker pull "$IMG" || die "cannot pull $IMG (check the tag and network access to the registry)"

  # The ping-socket sysctl is best effort. A runtime that refuses namespaced
  # net.* sysctls (gVisor, some managed or rootless daemons) must not turn "ICMP
  # would be nice" into "the Agent cannot be installed at all", so a rejected
  # start is retried without it and the loss is stated rather than discovered
  # later in the console.
  write_compose "$CONTAINER_VIEW"
  if ! START_ERR="$(compose up -d --remove-orphans 2>&1)"; then
    printf '%s\n' "$START_ERR" >&2
    # Only a complaint ABOUT the sysctl earns the retry. Every other failure
    # (bad tag, port clash, daemon error) fails identically the second time, and
    # blaming the sysctl for it sends the reader after the wrong thing.
    case "$START_ERR" in
      *sysctl*|*ping_group_range*) ;;
      *) die "could not start the Agent container (see the Docker error above)" ;;
    esac
    log "this Docker runtime refused net.ipv4.ping_group_range (see above); starting without it"
    log "  the Agent will report ICMP probing and gateway probing as unsupported"
    write_compose false
    compose up -d --remove-orphans
  fi

  log "verifying server connectivity and enrolling"
  if ! wait_enrolled docker exec nettact-agent test -f /agent-data/agent.json; then
    docker logs --tail 30 nettact-agent >&2 || true
    compose down --remove-orphans >/dev/null 2>&1 || true
    die "INSTALL FAILED: the Agent could not enroll with $SERVER_URL (see its log above). The container was removed; fix the problem, then generate a token in the console (for a reinstall of this machine, open the Agent in the console and choose Reinstall) and re-run this command."
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
    compose down --remove-orphans >/dev/null 2>&1 || true
    die "INSTALL FAILED: the Agent enrolled but did not stay running (see its log above). The container was removed; fix the problem, then generate a token in the console (for a reinstall of this machine, open the Agent in the console and choose Reinstall) and re-run this command."
  fi
  if $AUTO_UPDATE; then
    # Install only after enrollment and the stability dwell. The timer executes
    # as this Docker user so daemon access, registry credentials and contexts are
    # the same as they were during installation. All long-lived paths are baked
    # in as resolved absolute paths; no systemd working directory or ~ expansion
    # is involved.
    INSTALL_USER="$(id -un)"
    INSTALL_HOME="${HOME:-}"
    if [ -z "$INSTALL_HOME" ] && command -v getent >/dev/null 2>&1; then
      INSTALL_HOME="$(getent passwd "$(id -u)" | cut -d: -f6 || true)"
    fi
    [ -n "$INSTALL_HOME" ] && [ -d "$INSTALL_HOME" ] || die "cannot resolve the installing user's home directory for Docker credentials"
    INSTALL_HOME="$(cd "$INSTALL_HOME" && pwd -P)"
    printf -v INSTALL_DIR_Q '%q' "$INSTALL_DIR"
    printf -v DOCKER_BIN_Q '%q' "$DOCKER_BIN"
    SYSTEMD_HOME="$(printf '%s' "$INSTALL_HOME" | sed 's/\\/\\\\/g; s/"/\\"/g; s/%/%%/g')"

    unit_dir="$(mktemp -d)"
    trap 'rm -rf "$unit_dir"' EXIT
    cat > "$unit_dir/update.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR=$INSTALL_DIR_Q
DOCKER_BIN=$DOCKER_BIN_Q
old_image="\$("\$DOCKER_BIN" inspect --format '{{.Image}}' nettact-agent 2>/dev/null || true)"
"\$DOCKER_BIN" compose --project-directory "\$INSTALL_DIR" --env-file "\$INSTALL_DIR/.env" -f "\$INSTALL_DIR/docker-compose.yml" pull agent
"\$DOCKER_BIN" compose --project-directory "\$INSTALL_DIR" --env-file "\$INSTALL_DIR/.env" -f "\$INSTALL_DIR/docker-compose.yml" up -d --no-deps agent
new_image="\$("\$DOCKER_BIN" inspect --format '{{.Image}}' nettact-agent)"
if [ -n "\$old_image" ] && [ "\$old_image" != "\$new_image" ]; then
  "\$DOCKER_BIN" image rm "\$old_image" >/dev/null 2>&1 || true
fi
EOF
    cat > "$unit_dir/nettact-agent-docker-update.service" <<EOF
[Unit]
Description=Update the NetTact Agent container
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=$INSTALL_USER
Environment="HOME=$SYSTEMD_HOME"
ExecStart=$DOCKER_UPDATE_SCRIPT
EOF
    cat > "$unit_dir/nettact-agent-docker-update.timer" <<'EOF'
[Unit]
Description=Check daily for NetTact Agent container updates

[Timer]
OnBootSec=15min
OnUnitActiveSec=24h
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
    as_root install -d -m 0755 /usr/local/lib/nettact-agent-docker
    as_root install -m 0755 "$unit_dir/update.sh" "$DOCKER_UPDATE_SCRIPT"
    as_root install -m 0644 "$unit_dir/nettact-agent-docker-update.service" "$DOCKER_UPDATE_SERVICE"
    as_root install -m 0644 "$unit_dir/nettact-agent-docker-update.timer" "$DOCKER_UPDATE_TIMER"
    as_root systemctl daemon-reload
    as_root systemctl enable --now nettact-agent-docker-update.timer
    trap - EXIT
    rm -rf "$unit_dir"
    log "Daily automatic Agent container updates enabled"
  fi
  log "SUCCESS: Agent enrolled and running"
  log "  deployment: $INSTALL_DIR   (cd there for: docker compose ps | logs -f | down)"
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
    die "INSTALL FAILED: the Agent could not enroll with $SERVER_URL (see its log above). Nothing was left running; fix the problem, then generate a token in the console (for a reinstall of this machine, open the Agent in the console and choose Reinstall) and re-run this command."
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
    die "INSTALL FAILED: the Agent enrolled but did not stay running (see its log above). Nothing was left running; fix the problem, then generate a token in the console (for a reinstall of this machine, open the Agent in the console and choose Reinstall) and re-run this command."
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
    die "INSTALL FAILED: the Agent could not enroll with $SERVER_URL (see its log above). Nothing was left running; fix the problem, then generate a token in the console (for a reinstall of this machine, open the Agent in the console and choose Reinstall) and re-run this command."
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
    die "INSTALL FAILED: the Agent enrolled but did not stay running (see its log above). Nothing was left running; fix the problem, then generate a token in the console (for a reinstall of this machine, open the Agent in the console and choose Reinstall) and re-run this command."
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
