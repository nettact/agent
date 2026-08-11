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

# --- reading the agent's status document -------------------------------------

# Per-boot bookkeeping for launch.sh, beside the status file it reads.
#
# On tmpfs, and by design rather than by accident: every value here answers a
# question about THIS boot ("have we already checked for a newer binary", "have
# we already put this failure in the log"), and a reboot is a legitimate reason
# to ask both again. Putting them on the overlay would also spend flash erase
# cycles on files rewritten by a respawn loop — the one situation where they are
# touched most often and matter least. Overridable only so the offline test
# harness can point them somewhere hermetic.
NETTACT_RUN_DIR="${NETTACT_RUN_DIR:-/tmp/nettact}"
NETTACT_VERSION_STAMP="$NETTACT_RUN_DIR/version-checked"
NETTACT_REASON_STAMP="$NETTACT_RUN_DIR/reason-reported"

# The download helper, as a variable for the same test-harness reason.
NETTACT_FETCH="${NETTACT_FETCH:-/usr/lib/nettact/fetch.sh}"

# nettact_status_fatal <document> — the one-line reason the agent gave up, or
# nothing while it is still running.
#
# `sed` rather than a JSON parser because there is no JSON parser in this shell,
# and the agent guarantees the property that makes the expression exact: the
# value of "fatal" never contains a quote or a backslash (see the field's comment
# in agentrt/status.go). Any OTHER string in the document may, but only as `\"`,
# which cannot produce the unescaped `"fatal":"` this matches — so the greedy
# `.*` has exactly one candidate to find.
nettact_status_fatal() {
	printf '%s' "$1" | sed -n 's/.*"fatal":"\([^"]*\)".*/\1/p' | head -n 1
}

# nettact_status_is_final <document> — true when this document describes an agent
# that has STOPPED for a reason, rather than one that is running or restarting.
#
# It is the one rule that decides whether a status document may outlive the
# process that wrote it, and it lives here because two callers must never
# disagree about it: launch.sh deletes the file it does not apply to (so the page
# cannot show a dead process's last state during a respawn), and the rpcd backend
# passes through the file it does apply to (so the page CAN show the one state
# worth reading, whose process is by definition gone).
#
# Two shapes qualify. A document in which every server is terminal — every, not
# any, because with several configured a dead process can leave one terminal row
# beside another still claiming "connected", and waving the whole thing through
# on the strength of the first would present that stale row as current. And a
# document carrying a fatal reason, which is the process-level failure that
# happens before any server row exists at all; counting states would score that
# zero and throw away the only sentence there is.
#
# Returns non-zero for "not final", so call it from an `if` — both callers run
# under `set -e`.
nettact_status_is_final() {
	local doc states terminals
	doc="$1"
	[ -n "$doc" ] || return 1
	[ -z "$(nettact_status_fatal "$doc")" ] || return 0
	# `tr -d ' '` because some wc implementations pad the count. Spelled as a
	# literal space rather than a character class: `tr -d '[:space:]'` deleting the
	# characters of the class name instead of whitespace is a divergence this
	# package has already been bitten by on a real device.
	states="$(printf '%s' "$doc" | grep -o '"state":"[a-z_]*"' | wc -l | tr -d ' ')"
	terminals="$(printf '%s' "$doc" | grep -o '"state":"terminal"' | wc -l | tr -d ' ')"
	[ "$states" -ge 1 ] && [ "$states" = "$terminals" ]
}

# nettact_report_terminal_reason — put the previous agent's parting reason into
# syslog, once.
#
# The agent already writes that reason to its own stderr, and on a router that is
# not enough: procd's log reader routinely loses what a process wrote in the
# instant before it exited, which is exactly when this line is written. The field
# evidence is a router whose syslog carried the agent's FIRST line ("using config
# file …") and not its last — the one naming a schema version the server would
# not accept — leaving its owner with a status page that could only say "not
# running".
#
# So the durable record is the status file, written by the process that failed,
# and this republishes it from the wrapper that starts the next one. That
# ordering is the reason it belongs at the top of launch.sh: by the time it runs,
# the agent that wrote the document is already gone.
#
# Deduplicated against the last reason reported this boot, and that is not
# tidiness. procd respawns every ten seconds forever, so an unconditional line
# would be some eight thousand identical entries a day in a ring buffer thirty
# lines of which reach the status page — it would bury everything else the agent
# has to say, including the next, different failure.
#
# Never fatal: a diagnostic that can stop the agent starting is worse than none.
nettact_report_terminal_reason() {
	local doc reason last
	[ -s "$NETTACT_STATUS_FILE" ] || return 0
	doc="$(cat "$NETTACT_STATUS_FILE" 2>/dev/null)" || return 0
	reason="$(nettact_status_fatal "$doc")"
	[ -n "$reason" ] || return 0

	last=""
	if [ -f "$NETTACT_REASON_STAMP" ]; then
		last="$(cat "$NETTACT_REASON_STAMP" 2>/dev/null)" || last=""
	fi
	[ "$reason" != "$last" ] || return 0

	nettact_err "the agent stopped and will not recover on its own: $reason"
	mkdir -p "$NETTACT_RUN_DIR" 2>/dev/null || true
	printf '%s\n' "$reason" > "$NETTACT_REASON_STAMP" 2>/dev/null || true
	return 0
}

# --- keeping the binary current ----------------------------------------------

# How long a version check holds for, and how long one may take.
#
# Six hours is chosen against the respawn loop, not against the release cadence.
# procd restarts a failing agent every ten seconds and launch.sh runs each time,
# so an ungated check would be a request to the download source every ten seconds
# from every broken router in the fleet — the shape of a self-inflicted denial of
# service, arriving exactly when something is already wrong. One check, then four
# more that day, is enough to pick up a fix published while the router was
# looping, at one four-hundredth of the traffic.
#
# The resolve is bounded because a default route is not a working uplink: this
# runs after launch.sh has waited for one, and a route to an ISP that is down
# still resolves nothing. Fifteen seconds is far longer than a few hundred bytes
# need and far shorter than the five-minute waits above it.
NETTACT_VERSION_CHECK_INTERVAL="${NETTACT_VERSION_CHECK_INTERVAL:-21600}"
NETTACT_RESOLVE_TIMEOUT="${NETTACT_RESOLVE_TIMEOUT:-15}"

# nettact_mark_version_checked — record that the binary is known current now.
#
# Called after a download, so a boot that had to fetch a binary anyway does not
# then ask the same source what the newest version is: it has just been told.
nettact_mark_version_checked() {
	mkdir -p "$NETTACT_RUN_DIR" 2>/dev/null || true
	date +%s > "$NETTACT_VERSION_STAMP" 2>/dev/null || true
	return 0
}

# nettact_check_binary_version — install the published version when the one on
# this device is not it.
#
# The problem it closes: launch.sh used to ask only whether a binary EXISTS, so a
# router that downloaded the agent the day before a release ran that day's build
# until something removed the file. In RAM mode that is until the next reboot; in
# flash mode it is indefinite. A real device sat twenty-one hours on a build whose
# wire schema the server had since stopped accepting, in a respawn loop, with
# nothing anywhere saying why.
#
# What it deliberately does NOT do is turn that existence check into a download.
# Every failure here — no uplink, an unreachable mirror, a transfer that dies
# halfway — returns 0 and leaves the caller to exec the binary already present. A
# boot with the WAN down must still start the agent it has; that is the property
# the existence-only check had, and it is the one property this must not spend.
#
# Three decisions worth stating, because each has an obvious alternative:
#
#   * The stamp is written BEFORE the network work, not after a successful check.
#     A mirror that is down would otherwise leave no stamp, and the respawn loop
#     would retry it every ten seconds — hammering the one thing already failing.
#     The stamp means "we tried", which is what the interval has to count.
#
#   * The versions are compared before anything is downloaded. `fetch.sh install`
#     is already idempotent (it verifies and skips a byte-identical file), but it
#     learns that by transferring eleven megabytes first. Resolving the tag costs
#     a few hundred bytes, and on a router with a pinned version it costs nothing
#     at all — `fetch.sh resolve` answers a pin without touching the network.
#
#   * The resolved tag is passed to `install` rather than letting it resolve
#     again. Two resolves can straddle a release being published, and the second
#     would then fetch a binary against a checksum list from the first.
#
# The gate is time, not "has this router ever connected to a server". That was the
# tempting one — a router that has never worked is not obviously worth a round
# trip — and it is wrong for the exact case that motivated this: the device that
# went stale had never enrolled, BECAUSE the build it was stuck on was the reason
# the server refused it. A gate on prior success would have skipped precisely the
# router that needed the check.
#
# Nor is it a substitute for the nightly auto_update job. A healthy router that
# never reboots never runs this function again after boot, and cron is the only
# thing that reaches it; this covers the boot and the respawn loop, which is
# everything cron does not.
nettact_check_binary_version() {
	local bin now last have want
	bin="$(nettact_bin)"
	# Nothing to compare against, and nothing to fall back on if a download fails:
	# obtaining a binary at all is the caller's step, and it runs before this one.
	[ -x "$bin" ] || return 0

	now="$(date +%s)"
	last=0
	if [ -f "$NETTACT_VERSION_STAMP" ]; then
		last="$(cat "$NETTACT_VERSION_STAMP" 2>/dev/null)" || last=0
	fi
	# A stamp that is not a plain number is treated as no stamp. The leading-zero
	# strip is the same guard nettact_update_hhmm carries: POSIX `$((...))` reads a
	# leading zero as octal, so `08` is not eight but a syntax error — one that
	# would abort this function halfway under `set -e`, before the exec that starts
	# the agent.
	case "$last" in ''|*[!0-9]*) last=0 ;; esac
	last="${last#"${last%%[!0]*}"}"
	[ -n "$last" ] || last=0
	if [ "$((now - last))" -lt "$NETTACT_VERSION_CHECK_INTERVAL" ]; then
		return 0
	fi
	nettact_mark_version_checked

	have="$("$bin" --version 2>/dev/null | awk 'NR==1 {print $NF}')" || have=""
	# A binary that cannot say what it is may be a truncated download; replacing it
	# on that guess would spend an 11 MB transfer on a hunch, and the next start
	# fails the same way with the same evidence. Leave it to a human.
	[ -n "$have" ] || return 0

	want="$(nettact_resolve_version)" || want=""
	if [ -z "$want" ]; then
		nettact_log "could not reach the download source to check for a newer agent; continuing with $have"
		return 0
	fi
	if [ "$have" = "$want" ]; then
		nettact_log "agent $have is current"
		return 0
	fi

	# Worded for both cases this covers. With `version` at its default the target
	# is whatever was published last, and this is the drift closing; with a pinned
	# tag it is that tag, and this is a router being put back on the release its
	# owner chose — which is the same operation, in the other direction.
	nettact_log "agent $have should be $want; updating before start"
	if ! "$NETTACT_FETCH" install "$want"; then
		nettact_err "could not install agent $want; starting $have instead"
	fi
	return 0
}

# nettact_resolve_version — the release tag this router should be running, or
# nothing. Bounded, because its caller is on the path to starting the agent.
nettact_resolve_version() {
	if command -v timeout >/dev/null 2>&1; then
		timeout "$NETTACT_RESOLVE_TIMEOUT" "$NETTACT_FETCH" resolve 2>/dev/null
	else
		"$NETTACT_FETCH" resolve 2>/dev/null
	fi
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
