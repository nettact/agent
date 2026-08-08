# Shared paths and config accessors for the NetTact OpenWrt package.
# Sourced by launch.sh, genconfig.sh, fetch.sh and the rpcd backend; not
# executable itself.

# Identity lives here and is never placed in the RAM tree: agent.key and
# agent.json are a few hundred bytes, and losing them would force the router to
# re-enroll (a one-time token the user no longer has) on every reboot.
NETTACT_CONF_DIR=/etc/nettact
NETTACT_DATA_DIR=/etc/nettact/data

# Where the downloaded binary goes, per mode.
NETTACT_FLASH_DIR=/usr/lib/nettact
NETTACT_RAM_DIR=/tmp/nettact

# The agent's connection-status file: which servers it is talking to, why it is
# not, when it will try again, and how much is queued. The LuCI status page reads
# it — a router owner has no terminal, so without it "the service is running" is
# the most the page could ever say.
#
# On tmpfs, and not negotiable: it is rewritten on every reconnect attempt, and a
# router that cannot reach its server retries for as long as that lasts. Putting
# it anywhere on the overlay would spend erase cycles on exactly the failure it
# exists to report. Overridable only so the offline test harness can point it
# somewhere hermetic.
NETTACT_STATUS_FILE="${NETTACT_STATUS_FILE:-/tmp/nettact/status.json}"

# The agent's YAML configuration, rendered from UCI by genconfig.sh.
#
# It lands on tmpfs, not flash, for two reasons that both matter on a router:
# the enrollment token never comes to rest on persistent storage a second time
# (UCI already holds it), and editing settings in LuCI does not spend overlay
# erase cycles on a file that is rewritten from UCI at every start anyway.
NETTACT_GEN_DIR=/var/etc/nettact
NETTACT_GEN_CONFIG=/var/etc/nettact/agent.yaml

# The escape hatch. An operator who needs something UCI does not model can drop
# a hand-written config at the agent's own conventional path; when it exists the
# init script uses it verbatim and generates nothing, so the two can never
# disagree about which file is live.
NETTACT_USER_CONFIG=/etc/nettact/agent.yaml

# nettact_cfg <option> [default] — read one UCI option, falling back to default
# when unset or empty. A `list` option comes back space-separated, which is the
# form genconfig.sh wants: neither a permission id nor an access selector can
# contain a space.
nettact_cfg() {
	local v
	v="$(uci -q get "nettact.main.$1" 2>/dev/null)"
	[ -n "$v" ] || v="$2"
	printf '%s' "$v"
}

# nettact_mode — 'ram' or 'flash'; anything unrecognised is treated as ram,
# which is the safe default (it cannot fill a small overlay).
nettact_mode() {
	case "$(nettact_cfg mode ram)" in
		flash) printf 'flash' ;;
		*) printf 'ram' ;;
	esac
}

# nettact_bin_dir / nettact_bin — where the agent binary lives in the current mode.
nettact_bin_dir() {
	if [ "$(nettact_mode)" = flash ]; then
		printf '%s' "$NETTACT_FLASH_DIR"
	else
		printf '%s' "$NETTACT_RAM_DIR"
	fi
}

nettact_bin() {
	printf '%s/nettact-agent' "$(nettact_bin_dir)"
}

# nettact_config_file — the configuration the agent will actually read, and
# nettact_config_is_generated — whether that file is ours to overwrite. Both
# answer from the same condition so no caller can act on half of it.
nettact_config_file() {
	if [ -f "$NETTACT_USER_CONFIG" ]; then
		printf '%s' "$NETTACT_USER_CONFIG"
	else
		printf '%s' "$NETTACT_GEN_CONFIG"
	fi
}

nettact_config_is_generated() {
	[ ! -f "$NETTACT_USER_CONFIG" ]
}

# nettact_prune_stale_binary — in ram mode, delete the copy of the agent that a
# previous flash mode left on the overlay.
#
# Switching to ram is what someone does BECAUSE flash is tight, so leaving ~11 MB
# behind defeats the whole point of the switch. Deleting a binary that is running
# right now is safe on Linux: the process keeps its open inode until it restarts.
#
# The flash directory itself is never removed — /usr/lib/nettact also holds
# common.sh, launch.sh, fetch.sh and genconfig.sh, so an rmdir here would take
# the package's own scripts with it. Only the two files fetch.sh creates go.
#
# The reverse case needs no code: a ram-mode leftover sits in /tmp and is gone
# after the next boot.
nettact_prune_stale_binary() {
	[ "$(nettact_mode)" = ram ] || return 0
	local bin="$NETTACT_FLASH_DIR/nettact-agent"
	local part="$NETTACT_FLASH_DIR/.nettact-agent.download"
	[ -e "$bin" ] || [ -e "$part" ] || return 0
	# Never fatal. launch.sh runs under `set -e`, and a read-only overlay is a
	# reason to log and carry on with the RAM copy — not to fail the start and
	# leave procd respawning.
	if rm -f "$bin" "$part" 2>/dev/null; then
		nettact_log "storage mode is ram; removed the agent binary left on flash"
	else
		nettact_err "could not remove the flash copy at $bin (continuing)"
	fi
	return 0
}

nettact_log() {
	logger -t nettact -p daemon.info -- "$@"
}

nettact_err() {
	logger -t nettact -p daemon.err -- "$@"
	echo "$@" >&2
}
