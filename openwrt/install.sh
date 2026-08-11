#!/bin/sh
# One-command NetTact Agent installer for OpenWrt: both packages, the UCI
# configuration, and a check that the router actually came online.
#
# This is a separate script from the module's install.sh rather than another
# branch inside it. That one is bash targeting systemd and launchd, unpacks a
# binary into /usr/local/bin, and WIPES the previous identity so the machine
# re-enrolls with the token it was given. Every one of those is wrong here: a
# router has BusyBox ash and procd, the packages deliberately ship no binary
# (fetch.sh downloads the one matching this CPU at first start), and the OpenWrt
# contract is the opposite one — /etc/nettact/data survives package removal and
# sysupgrade precisely so a reinstall never means enrolling again. Sharing code
# between the two would mean a script whose every step forked on the platform.
#
# POSIX sh only, and no `set -o pipefail`: BusyBox ash does not reliably have it.
set -eu

IPK_BASE="https://d.nettact.org/agent"
SERVER_URL="${NETTACT_AGENT_SERVER_URL:-}"
TOKEN="${NETTACT_AGENT_ENROLL_TOKEN:-}"
TOKEN_FILE=""
PERMISSIONS=""
MODE=""
VERSION=""
DOWNLOAD_BASE=""
TLS_INSECURE=false
AUTO_UPDATE=false
WITH_LUCI=true
REINSTALL=false
# The download is no longer inside this window — the binary is fetched
# synchronously below, before the service starts — so this covers enrollment and
# the first connection only. Still generous rather than tight: launch.sh blocks
# on a plausible clock and a default route before the agent runs at all, and on a
# router that has just come up both can take a while.
WAIT_SECONDS=180

usage() {
	cat <<'EOF'
NetTact Agent installer for OpenWrt

Usage:
  openwrt.sh --server-url <url> --token <one-time-token> [options]

Installs the nettact-agent and luci-app-nettact packages, writes the connection
settings into /etc/config/nettact, starts the service, and waits until the
router reports itself connected. Re-running it is safe: the agent's identity in
/etc/nettact/data is never touched, so an already-enrolled router keeps its
credential and does not need a token.

Every run also refreshes the agent binary to the configured version, so
re-running this is how a router is upgraded — and why a router that has been
running an older agent does not stay on it.

Options:
  --token-file <path>  Read the one-time token from a file instead of the
                       command line.
  --permissions <list> Comma-separated local permission policy, or the literal
                       "default" (the agent's built-in grant) or "none" (grant
                       nothing). A list REPLACES the built-in grant rather than
                       adding to it. Omitting the option leaves whatever this
                       router already has; passing "default" resets it. The
                       NetTact console's Agent page generates a ready-made
                       value for you.
  --mode ram|flash     Where the agent binary lives. ram (default) downloads it
                       to /tmp on every boot and uses no flash at all; flash
                       downloads it once to /usr/lib/nettact and needs ~12 MB
                       free on the overlay but boots offline.
  --version <tag>      Pin the agent binary to a release tag (default: latest).
  --auto-update        Check daily for a newer agent binary and install it,
                       restarting the service only when it actually changed.
                       The check runs at a fixed time between 02:00 and 05:00
                       derived from this router's MAC address. Cannot be
                       combined with a pinned --version. Off unless this option
                       is on THIS command line: re-running without it turns
                       automatic updates back off.
  --download-base <url>
                       Where the agent BINARY is fetched from; point it at a
                       local mirror to keep the router off the internet.
  --ipk-base <url|dir> Where the two .ipk PACKAGES come from (default:
                       https://d.nettact.org/agent). A local directory works
                       too, which is how an unreleased build is tested.
  --tls-insecure       Accept a server certificate that does not verify. Only
                       for a private CA or an IP-address server you control.
  --no-luci            Install the agent package without the LuCI pages.
  --reinstall          Enroll again with the token given here instead of the
                       credential this router already has. Needed for a console
                       "Reinstall", which mints a token bound to one agent:
                       without this the agent keeps its existing credential and
                       the token is never used. The old credential and queued
                       telemetry are discarded, and only once the configuration
                       has been written — so a bad option or a failed UCI write
                       leaves the router exactly as it was. Identity is
                       otherwise preserved.
  --wait <seconds>     How long to wait for the router to come online
                       (default: 180). 0 skips the check entirely.

Environment:
  NETTACT_AGENT_SERVER_URL, NETTACT_AGENT_ENROLL_TOKEN are read when the
  matching option is absent.
EOF
}

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }

while [ $# -gt 0 ]; do
	case "$1" in
		--server-url) SERVER_URL="${2:?--server-url needs a value}"; shift 2 ;;
		--token) TOKEN="${2:?--token needs a value}"; shift 2 ;;
		--token-file) TOKEN_FILE="${2:?--token-file needs a value}"; shift 2 ;;
		--permissions) PERMISSIONS="${2:?--permissions needs a value}"; shift 2 ;;
		--mode) MODE="${2:?--mode needs a value}"; shift 2 ;;
		--version) VERSION="${2:?--version needs a value}"; shift 2 ;;
		--download-base) DOWNLOAD_BASE="${2:?--download-base needs a value}"; shift 2 ;;
		--ipk-base) IPK_BASE="${2:?--ipk-base needs a value}"; shift 2 ;;
		--tls-insecure) TLS_INSECURE=true; shift ;;
		--auto-update) AUTO_UPDATE=true; shift ;;
		--no-luci) WITH_LUCI=false; shift ;;
		--reinstall) REINSTALL=true; shift ;;
		--wait) WAIT_SECONDS="${2:?--wait needs a value}"; shift 2 ;;
		-h|--help) usage; exit 0 ;;
		*) die "unknown option: $1 (see --help)" ;;
	esac
done

# --- validation --------------------------------------------------------------
# Everything that can be judged without touching the router is judged here.
# Installing two packages and then failing on a typo'd permission id would leave
# a router carrying software it never got to use.

[ "$(id -u)" = 0 ] || die "this installer must run as root"

[ -n "$SERVER_URL" ] || die "--server-url is required"
# Same rule as the Linux/macOS installer: a pin says "stay on this version", and
# a nightly updater would walk straight past it.
if $AUTO_UPDATE && [ -n "$VERSION" ] && [ "$VERSION" != latest ]; then
	die "--auto-update cannot be combined with a pinned --version"
fi

case "$MODE" in
	''|ram|flash) ;;
	*) die "--mode must be ram or flash (got '$MODE')" ;;
esac

case "$WAIT_SECONDS" in
	''|*[!0-9]*) die "--wait needs a whole number of seconds" ;;
esac

if [ -n "$TOKEN" ] && [ -n "$TOKEN_FILE" ]; then
	die "--token and --token-file are mutually exclusive"
fi
if [ -n "$TOKEN_FILE" ] && [ ! -r "$TOKEN_FILE" ]; then
	die "token file not readable: $TOKEN_FILE"
fi

# The console shows this command with a placeholder token until one is
# generated, and it is copied and run in that state often enough to be worth
# naming: the router would install two packages, write its config and then sit
# in a retry loop against a server that answers 401. Say what actually went
# wrong, before anything on the router is touched.
case "$TOKEN" in
	'<enrollment-token>')
		die "the --token value is still the console's placeholder, so no enrollment token was ever generated.
In the NetTact console open Agents -> Add agent, click \"Generate token\", then copy this command again from that page." ;;
esac

case "$SERVER_URL$TOKEN" in
	*'
'*) die "server URL and token must each be a single line" ;;
esac

# Normalized and checked the same way the native installer does it: the agent
# rejects an unsatisfiable policy at startup, and a router that fails there sits
# in a procd respawn loop rather than telling anyone why. Whitespace is stripped
# rather than rejected so a value pasted out of the console still works.
#
# The whitespace characters are spelled out rather than written as the POSIX
# class: BusyBox tr does not honour `[:space:]` and deletes the literal
# characters of it instead, which silently turns probe.icmp into rob.im — a
# permission id the agent then refuses to start on.
if [ -n "$PERMISSIONS" ]; then
	PERMISSIONS="$(printf '%s' "$PERMISSIONS" | tr -d ' \t\n\r\f\v')"
	case "$PERMISSIONS" in
		"") die "--permissions needs a value (use \"none\" for an empty grant)" ;;
		default|none) ;;
		*'*'*|all|ALL) die "--permissions does not accept wildcards; list explicit permissions or \"none\"" ;;
	esac
	# A value of only separators would write a permission list with no entries,
	# which the agent reads as "not configured" and answers with the full default
	# grant — the opposite of the restriction that was asked for, silently.
	if [ "$PERMISSIONS" != none ] && [ "$PERMISSIONS" != default ] && [ -z "$(printf '%s' "$PERMISSIONS" | tr -d ',')" ]; then
		die "--permissions lists no permissions; pass explicit ids or \"none\" for an empty grant"
	fi
fi

# opkg, specifically. An image built with apk instead (OpenWrt snapshots and
# what follows 24.10) has no way to install these packages today, and saying so
# is worth more than "opkg: not found" from three lines further down.
if ! command -v opkg >/dev/null 2>&1; then
	if command -v apk >/dev/null 2>&1; then
		die "this image uses apk; the NetTact packages are opkg-format today.
See https://nettact.org/en/openwrt for the manual route, or report the image you are on."
	fi
	die "opkg not found — this installer is for OpenWrt and its derivatives"
fi
command -v uci >/dev/null 2>&1 || die "uci not found — this installer is for OpenWrt and its derivatives"

# Whether this router can enroll at all is decided HERE, before a single package
# is installed. Finding out afterwards would leave a fresh router carrying two
# packages it was never able to use, which is precisely what this section exists
# to prevent.
#
# The data directory is spelled out rather than taken from common.sh: that file
# ships with the package this has not installed yet. It is the same constant —
# NETTACT_DATA_DIR — and the package's own copy governs from the moment it is
# sourced below.
DATA_DIR=/etc/nettact/data

# default_credential — does agent.json hold a usable credential for the server
# name this installer's single-server config uses?
#
# File size proves nothing. Credentials are keyed by SERVER NAME, and a router
# being moved off multi-server mode has entries named `home` or `work` and none
# named `default` — so "the file is non-empty" would let the install proceed
# without a token, rewrite the config into single mode, and leave the agent with
# no credential and nothing to enroll with. A truncated or hand-mangled file
# passes a size test too.
#
# jsonfilter is part of the OpenWrt base system (libubox). If some derivative
# lacks it, this reports "not enrolled" rather than guessing at JSON with a
# regex: the cost is an unnecessary --token, and the alternative is a wrong
# answer in the direction that breaks the router.
default_credential() {
	[ -s "$DATA_DIR/agent.json" ] || return 1
	command -v jsonfilter >/dev/null 2>&1 || return 1
	[ -n "$(jsonfilter -i "$DATA_DIR/agent.json" -e '@.servers.default.agent_token' 2>/dev/null)" ]
}

ENROLLED=false
if ! $REINSTALL && default_credential; then ENROLLED=true; fi

# A reinstall is the one case where keeping the identity is wrong. The console
# mints a token bound to one agent, and the agent prefers a saved credential over
# any token — so without clearing it the token is never used and the "reinstall"
# silently does nothing but restart the service.
if $REINSTALL && [ -z "$TOKEN" ] && [ -z "$TOKEN_FILE" ]; then
	die "--reinstall needs a token: it re-enrolls with the token given here instead of the saved credential"
fi

if [ -z "$TOKEN" ] && [ -z "$TOKEN_FILE" ]; then
	if $ENROLLED; then
		log "already enrolled; keeping the credential in $DATA_DIR"
	elif [ -s "$DATA_DIR/agent.json" ]; then
		die "--token is required: $DATA_DIR/agent.json holds no credential named 'default', which is the name a single-server install uses. A router previously reporting to several servers keeps its credentials under their own names. Generate a token in the console under Agents -> Enrollment."
	else
		die "--token is required (or --token-file). Generate one in the console under Agents -> Enrollment."
	fi
fi

# --- packages ----------------------------------------------------------------

# Non-fatal: the two .ipk are installed from an explicit URL or path, so a stale
# or unreachable package feed only matters for ca-bundle below.
log "refreshing the package lists"
opkg update >/dev/null 2>&1 || warn "opkg update failed; continuing with the package lists already on the router"

# HTTPS for opkg (and for fetch.sh later) needs two things: a CA store and a TLS
# transport for libustream. Official images ship both; a stripped build may have
# neither, and the failure without them is an SSL error at download time that
# names no missing package.
#
# The transport is installed only when NO provider is present. `libustream-mbedtls`
# is the usual one, but openssl and wolfssl variants exist and satisfy the same
# dependency — installing mbedtls on top of a working openssl image would be a
# swap nobody asked for.
if ! opkg list-installed 2>/dev/null | grep -q '^ca-bundle '; then
	log "installing ca-bundle (needed to fetch over HTTPS)"
	opkg install ca-bundle >/dev/null 2>&1 || warn "could not install ca-bundle; an HTTPS download may fail"
fi
if ! opkg list-installed 2>/dev/null | grep -q '^libustream-'; then
	log "installing libustream-mbedtls (no TLS transport present)"
	opkg install libustream-mbedtls >/dev/null 2>&1 || warn "could not install libustream-mbedtls; an HTTPS download may fail"
fi

log "installing nettact-agent from $IPK_BASE"
opkg install "$IPK_BASE/nettact-agent.ipk" || die "could not install nettact-agent"
if $WITH_LUCI; then
	log "installing luci-app-nettact"
	opkg install "$IPK_BASE/luci-app-nettact.ipk" || die "could not install luci-app-nettact"
fi

# Paths and helpers come from the package that was just installed rather than
# being repeated here, so this script cannot drift from where the agent actually
# keeps its identity and status.
. /usr/lib/nettact/common.sh

# --- configuration -----------------------------------------------------------

uci_set() { uci -q set "nettact.main.$1=$2"; }

uci -q get nettact.main >/dev/null 2>&1 || uci set nettact.main=nettact

# A router already set up for several servers has its settings in `config server`
# sections, which single mode ignores. Overwriting that silently would take those
# servers off the air with no message anywhere.
if [ "$(uci -q get nettact.main.server_mode || true)" = multi ]; then
	warn "this router was configured for several servers (server_mode=multi); switching it to the single server given here. The 'config server' sections stay in /etc/config/nettact but are no longer used."
fi


log "writing /etc/config/nettact"
uci_set server_mode single
uci_set server_url "$SERVER_URL"
if [ -n "$TOKEN" ]; then
	uci_set enroll_token "$TOKEN"
	uci -q delete nettact.main.enroll_token_file 2>/dev/null || true
fi
if [ -n "$TOKEN_FILE" ]; then
	uci_set enroll_token_file "$TOKEN_FILE"
	uci -q delete nettact.main.enroll_token 2>/dev/null || true
fi
if [ -n "$MODE" ]; then uci_set mode "$MODE"; fi
if [ -n "$VERSION" ]; then uci_set version "$VERSION"; fi
# Written either way, for the same reason tls_insecure is (below): the console
# renders this command with every choice stated, so an absent flag has to MEAN
# off. Re-running the command with the box unticked must actually turn automatic
# updates off, not inherit the previous run's answer.
if $AUTO_UPDATE; then uci_set auto_update 1; else uci_set auto_update 0; fi
if [ -n "$DOWNLOAD_BASE" ]; then uci_set download_base "$DOWNLOAD_BASE"; fi
# Written either way, never just when the flag is present. A router that was
# once pointed at a private-CA server keeps tls_insecure=1 in its config, and
# re-pointing it at a new server without the flag would silently carry disabled
# certificate verification across — the one setting where inheriting a previous
# answer is a security decision nobody made.
if $TLS_INSECURE; then uci_set tls_insecure 1; else uci_set tls_insecure 0; fi

# The permission list is REPLACED rather than added to, matching what the grant
# itself does. Leaving the previous entries in place would union this install's
# choice with the last one's, which is the one direction a permission change must
# never go by accident.
case "$PERMISSIONS" in
	"") ;;
	default)
		# An explicit reset: the console shows "recommended", so the command has to
		# SAY so — leaving the option out would keep whatever narrower or broader
		# grant this router was carrying.
		uci_set permission_mode default
		uci -q delete nettact.main.permissions 2>/dev/null || true
		;;
	none)
		uci_set permission_mode none
		uci -q delete nettact.main.permissions 2>/dev/null || true
		;;
	*)
		uci_set permission_mode custom
		uci -q delete nettact.main.permissions 2>/dev/null || true
		oldifs="$IFS"
		IFS=','
		for perm in $PERMISSIONS; do
			if [ -n "$perm" ]; then uci add_list "nettact.main.permissions=$perm"; fi
		done
		IFS="$oldifs"
		;;
esac

# Last, and deliberately: the package ships enabled='0' so that installing it can
# never make a router report to a server nobody configured. That property should
# hold right up to the moment there IS one.
uci_set enabled 1
uci commit nettact

# --- the binary ---------------------------------------------------------------

# Every run refreshes the binary, and it happens HERE rather than being left to
# launch.sh, which only asks whether a binary exists — never which version it is.
# That existence check is right for a boot (re-resolving `latest` on every respawn
# would put a download in the path of a crash loop), but it means a router that
# downloaded the agent before a release keeps running the old one for as long as
# it stays up. In RAM mode that is bounded by the next reboot; in flash mode it is
# forever. Either way the symptom is the worst kind: an agent that starts, fails
# to enroll against a server that has moved on, and respawns every 10s with the
# reason buried in syslog.
#
# So re-running this script is the upgrade path, and it has to actually download.
# fetch.sh is already idempotent — it resolves the version, verifies SHA256, and
# leaves the file alone when the bytes match — so the cost of the guarantee is one
# download that usually changes nothing.
#
# Two constraints fix this position exactly. After `uci commit`: mode, version and
# download_base all come from UCI, so fetching earlier would fetch for the
# PREVIOUS configuration. And before the --reinstall wipe below: a failed download
# then aborts with the old credential and queue still intact, which is the same
# promise the rest of this script makes — nothing destructive happens until
# everything that can fail has succeeded. Replacing the binary under the running
# agent is safe; Linux keeps the old inode alive until the restart below.
log "refreshing the agent binary"
if ! /usr/lib/nettact/fetch.sh install "$VERSION"; then
	# A binary already on the router is worth more than a failed refresh: the
	# usual cause is a mirror or an uplink being briefly unreachable, and
	# refusing to finish a re-run that was only meant to change a permission
	# would be its own kind of broken. But it is a warning, not silence — this is
	# exactly the state where the agent about to start may be too old for its
	# server, and the online check below is what catches that.
	if [ -x "$(nettact_bin)" ]; then
		warn "could not refresh the agent binary; continuing with the copy already at $(nettact_bin). If this router does not come online below, an out-of-date agent is the first thing to suspect: re-run once the download source is reachable."
	else
		die "could not download the agent binary, and this router has none to fall back on. Check --download-base/--version and that the router can reach it, then re-run. Nothing has been discarded: this router's identity and queued telemetry are as they were."
	fi
else
	# The version this router should run has just been established, so the boot
	# check in launch.sh has nothing left to ask. Saying so here spares the
	# restart below a second round trip to the same source, at the one moment
	# this script is already waiting on the agent to come online.
	nettact_mark_version_checked
fi

# Now, and not before: the configuration is written and valid and the binary is in
# place, so this is the last point at which anything could still have aborted with
# the old credential intact. Stopped first because the running agent holds that
# credential in memory and would go on using it regardless of what is on disk.
if $REINSTALL; then
	log "reinstall: discarding the saved credential and queued telemetry"
	/etc/init.d/nettact stop >/dev/null 2>&1 || true
	rm -f "$NETTACT_DATA_DIR/agent.json"
	rm -rf "$NETTACT_DATA_DIR/wal"
fi

log "starting the service"
/etc/init.d/nettact enable
/etc/init.d/nettact restart

# --- did it actually come online? --------------------------------------------

# "The service is running" is not success: an unreachable server or a rejected
# token leaves procd respawning a binary that exits every time, which looks
# identical from the outside. The agent writes its own connection state, so ask
# that instead — and check the pid it names is alive, or a status file left by a
# previous run would answer for a process that is gone. Same technique the LuCI
# status page uses.
status_connected() {
	local blob pid
	[ -s "$NETTACT_STATUS_FILE" ] || return 1
	blob="$(cat "$NETTACT_STATUS_FILE" 2>/dev/null)" || return 1
	pid="$(printf '%s' "$blob" | sed -n 's/.*"pid":[[:space:]]*\([0-9][0-9]*\).*/\1/p')"
	[ -n "$pid" ] || return 1
	kill -0 "$pid" 2>/dev/null || return 1
	printf '%s' "$blob" | grep -q '"state"[[:space:]]*:[[:space:]]*"connected"'
}

diagnose() {
	printf '\n'
	if [ -s "$NETTACT_STATUS_FILE" ]; then
		printf 'Connection status (%s):\n' "$NETTACT_STATUS_FILE"
		cat "$NETTACT_STATUS_FILE"
		printf '\n'
	fi
	printf 'Recent log:\n'
	logread -e nettact 2>/dev/null | tail -n 15 || true
	cat <<EOF

Worth checking:
  logread -e nettact                     the service log
  cat $NETTACT_GEN_CONFIG   the configuration UCI produced
  /usr/lib/nettact/fetch.sh arch         the build this device resolves to
  /usr/lib/nettact/fetch.sh resolve      the release tag 'latest' points at
  $(nettact_bin) --version   the agent this router will run
  ls -l $NETTACT_DATA_DIR/          agent.json present means enrollment succeeded

An agent that exits immediately, over and over, is most often one the server
refuses: a spent or wrong token, or a build too old for it. When it gives up for
a reason like that it records the reason in the "fatal" field of the connection
status printed above, and the next start repeats it into the system log — so
'logread -e nettact' should now say why. If neither carries it, run the agent
once in the foreground:
  NETTACT_AGENT_CONFIG_FILE=$NETTACT_GEN_CONFIG NETTACT_AGENT_DATA_DIR=$NETTACT_DATA_DIR $(nettact_bin)
EOF
}

if [ "$WAIT_SECONDS" = 0 ]; then
	log "skipping the online check (--wait 0)"
	exit 0
fi

log "waiting up to ${WAIT_SECONDS}s for the router to report itself connected"
deadline=$(( $(date +%s) + WAIT_SECONDS ))
saw_status=false
ticks=0
while [ "$(date +%s)" -lt "$deadline" ]; do
	if status_connected; then
		log "connected."
		printf '\n'
		printf '  mode        %s\n' "$(nettact_mode)"
		printf '  binary      %s\n' "$(nettact_bin)"
		printf '  identity    %s\n' "$NETTACT_DATA_DIR"
		printf '  LuCI        Services -> NetTact\n'
		printf '\nThe one-time token is spent; clearing it is optional:\n'
		printf '  uci delete nettact.main.enroll_token && uci commit nettact\n'
		exit 0
	fi
	if [ -s "$NETTACT_STATUS_FILE" ]; then saw_status=true; fi
	sleep 3
	# One line every ~15s rather than per poll: in RAM mode most of this window
	# is an 11 MB download, and three minutes of silence reads as a hang.
	ticks=$(( ticks + 1 ))
	if [ $(( ticks % 5 )) = 0 ]; then
		if $saw_status; then
			log "still connecting..."
		else
			log "waiting for the agent to start (it waits for the clock and a default route first)..."
		fi
	fi
done

# No fallback for a build that does not write a status file. The one this script
# just installed does, so "the file never appeared" means the agent is not
# running long enough to write it — a respawn loop, which is precisely the
# failure an install must not report as success. Accepting "the service is up and
# a credential exists" instead would pass a router that is crash-looping while
# holding a credential from a previous, different server.
printf 'ERROR: the router did not report itself connected within %ss\n' "$WAIT_SECONDS" >&2
diagnose >&2
exit 1
