# Shared paths and config accessors for the NetTact OpenWrt package.
# Sourced by launch.sh, fetch.sh and the rpcd backend; not executable itself.

# Identity lives here and is never placed in the RAM tree: agent.key and
# agent.json are a few hundred bytes, and losing them would force the router to
# re-enroll (a one-time token the user no longer has) on every reboot.
NETTACT_CONF_DIR=/etc/nettact
NETTACT_DATA_DIR=/etc/nettact/data

# Where the downloaded binary goes, per mode.
NETTACT_FLASH_DIR=/usr/lib/nettact
NETTACT_RAM_DIR=/tmp/nettact

# nettact_cfg <option> [default] — read one UCI option, falling back to default
# when unset or empty.
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

nettact_log() {
	logger -t nettact -p daemon.info -- "$@"
}

nettact_err() {
	logger -t nettact -p daemon.err -- "$@"
	echo "$@" >&2
}
