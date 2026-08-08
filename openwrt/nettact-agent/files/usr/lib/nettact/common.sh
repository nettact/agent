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

# --- automatic binary updates ------------------------------------------------

# The crontab line update.sh runs from, and the marker that identifies it. The
# marker is what makes the line ours to rewrite or remove without touching
# whatever else the owner has in root's crontab. The path is overridable only so
# the offline test harness can point it somewhere hermetic.
NETTACT_CRONTAB="${NETTACT_CRONTAB:-/etc/crontabs/root}"
NETTACT_CRON_MARK='# nettact-auto-update'

# nettact_update_hhmm — the daily update time for THIS router, as "minute hour".
#
# Spread across 02:00–04:59 rather than fixed, for the same reason the server's
# updater bakes a random time in that window: a fleet on one schedule arrives at
# the download source as a spike, and 03:00 sharp is when everything else on a
# router is already running. Derived from the first MAC address (hostname, then
# a constant, as fallbacks) instead of $RANDOM so it is STABLE: a value re-rolled
# at every service start would move the job around and, worse, rewrite the
# crontab on every boot.
nettact_update_hhmm() {
	local seed n
	seed="$(cat /sys/class/net/*/address 2>/dev/null | grep -v '^00:00:00:00:00:00$' | head -n 1)"
	# `|| true` on each fallback, and it is load-bearing rather than defensive.
	# An assignment takes the exit status of its command substitution, and as the
	# right operand of `||` that status is NOT exempt from `set -e` — so on a
	# device with no readable MAC, `uci` exiting 1 (no such option) aborts this
	# function halfway. It then returns an EMPTY string, and the caller writes a
	# crontab line with no minute and no hour:
	#
	#     " * * * /usr/lib/nettact/update.sh # nettact-auto-update"
	#
	# cron rejects that, so automatic updates silently never run and nothing
	# anywhere says why. launch.sh and the init script both run under `set -e`,
	# which is exactly where this would have bitten.
	[ -n "$seed" ] || seed="$(uci -q get system.@system[0].hostname 2>/dev/null)" || true
	[ -n "$seed" ] || seed=nettact
	n="$(printf '%s' "$seed" | md5sum | tr -dc '0-9' | cut -c1-6)" || true
	[ -n "$n" ] || n=137
	# Strip leading zeros before any arithmetic. POSIX `$((...))` reads a leading
	# zero as OCTAL, so a digest whose first six digits are e.g. 089123 is not a
	# large number here — it is a syntax error ("value too great for base"), which
	# aborts the command substitution and returns an EMPTY string. The caller then
	# writes a crontab line whose minute and hour fields are simply missing, cron
	# rejects the malformed entry, and automatic updates never run on that router
	# with nothing anywhere saying why. Which routers were affected depended on
	# their MAC, so it would have looked random.
	#
	# ${n#"${n%%[!0]*}"} removes the run of leading zeros; the || guards the case
	# where every digit was zero and the strip leaves nothing.
	n="${n#"${n%%[!0]*}"}"
	[ -n "$n" ] || n=137
	printf '%d %d' "$((n % 60))" "$((2 + (n / 60) % 3))"
}

# nettact_cron_lines_without_ours prints the crontab with our line removed.
nettact_cron_lines_without_ours() {
	[ -f "$NETTACT_CRONTAB" ] || return 0
	grep -v -- "$NETTACT_CRON_MARK" "$NETTACT_CRONTAB" 2>/dev/null || true
}

# nettact_write_cron makes our line in root's crontab exactly $1 (empty removes
# it), and does nothing at all when it already is.
#
# That last part is not an optimisation: the crontab lives on the overlay, and a
# rewrite on every service start would spend flash erase cycles to change
# nothing. It is also why the init script syncs on start only — a stop/start pair
# that removed the line and put it straight back would write twice per restart.
#
# Never fatal. A read-only overlay or a missing /etc/crontabs is a reason to log
# and carry on starting the agent, not to fail the service over its update job.
nettact_write_cron() {
	local want="$1" current tmp
	current="$(grep -- "$NETTACT_CRON_MARK" "$NETTACT_CRONTAB" 2>/dev/null || true)"
	[ "$current" = "$want" ] && return 0

	mkdir -p "$(dirname "$NETTACT_CRONTAB")" 2>/dev/null || true
	tmp="$NETTACT_CRONTAB.nettact.tmp"
	# `if` rather than `[ -n "$want" ] && printf`: a group's exit status is its
	# LAST command's, so the short-circuit form reports failure whenever $want is
	# empty — which is exactly the removal case, and it would take the removal
	# with it. The write it is guarding is the redirection, not the printf.
	{
		nettact_cron_lines_without_ours
		if [ -n "$want" ]; then printf '%s\n' "$want"; fi
	} > "$tmp" 2>/dev/null || {
		rm -f "$tmp" 2>/dev/null || true
		nettact_err "could not write $tmp (automatic updates unchanged)"
		return 0
	}
	if ! mv -f "$tmp" "$NETTACT_CRONTAB" 2>/dev/null; then
		rm -f "$tmp" 2>/dev/null || true
		nettact_err "could not update $NETTACT_CRONTAB (automatic updates unchanged)"
		return 0
	fi

	if [ -n "$want" ]; then
		nettact_log "automatic agent updates on: $want"
	else
		nettact_log "automatic agent updates off; cron entry removed"
	fi
	# busybox crond notices the file on its own within a minute; reloading only
	# when we actually wrote keeps the unchanged path free of side effects.
	/etc/init.d/cron reload >/dev/null 2>&1 || /etc/init.d/cron restart >/dev/null 2>&1 || true
	return 0
}

# nettact_sync_cron makes the update job match UCI: present when the service is
# enabled AND auto_update is on, absent otherwise.
nettact_sync_cron() {
	if [ "$(nettact_cfg enabled 0)" = 1 ] && [ "$(nettact_cfg auto_update 0)" = 1 ]; then
		nettact_write_cron "$(nettact_update_hhmm) * * * /usr/lib/nettact/update.sh $NETTACT_CRON_MARK"
	else
		nettact_write_cron ""
	fi
}

# nettact_remove_cron drops the job regardless of UCI — for package removal,
# where update.sh is about to stop existing.
nettact_remove_cron() {
	nettact_write_cron ""
}
