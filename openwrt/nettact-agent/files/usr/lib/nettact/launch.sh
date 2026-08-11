#!/bin/sh
# procd runs this, not the agent directly. It does the things that must happen
# between "the router finished booting" and "the agent can work" — report and
# tidy the previous process's status, wait for a clock and a route, make sure
# there is a binary and that it is the published one — then hands its own
# process over to the agent so procd keeps supervising the real thing rather
# than a wrapper.
#
# Failures here exit non-zero on purpose: procd's respawn is the retry loop, and
# an exit that lands in syslog is far easier to diagnose than a script that
# silently sleeps forever. The two steps added for diagnosis and for version
# drift are the exceptions and are written to be: neither may keep an agent that
# could run from running.
set -e

. /usr/lib/nettact/common.sh

BIN="$(nettact_bin)"

# 0. Deal with the previous process's status file, first thing.
#
#    An agent that was killed or crashed never got to remove its own, and procd
#    reports THIS wrapper as running from the moment it starts — while the waits
#    below can take ten minutes between them. Without this, the status page
#    would spend that whole window showing the dead process's last state, and
#    "Connected" is the most likely thing for it to have been.
#
#    A final document is the exception, and the only one. The agent writes it on
#    the way out precisely because it gave up for a reason no retry can fix — no
#    token, a refused enrollment, a credential it could not save, a configuration
#    it will not accept — and it is then respawned straight back into the same
#    wall. Deleting it here would mean the one state worth reading is erased
#    seconds after it is written, every time, and the page would show nothing but
#    startup states forever. It is replaced by the first real transition once the
#    agent below gets that far. nettact_status_is_final owns that rule, shared
#    with the rpcd backend so the two cannot disagree about which documents live.
#
#    Reporting comes before deleting for the obvious reason and one less obvious
#    one: the reason has to reach syslog even in the cases where the document is
#    NOT kept, and a status file that names a fatal reason is exactly the case
#    where the agent's own stderr did not make it.
nettact_report_terminal_reason
if ! nettact_status_is_final "$(cat "$NETTACT_STATUS_FILE" 2>/dev/null)"; then
	rm -f "$NETTACT_STATUS_FILE"
fi

# 1. A believable clock. Many routers have no RTC and boot in 1970, which makes
#    every server certificate "not yet valid" and the agent's first TLS dial fail
#    for a reason that looks nothing like a clock problem. sysntpd (START=98)
#    fixes it within seconds of the network coming up.
i=0
while [ "$(date -u +%Y)" -lt 2025 ]; do
	i=$((i + 1))
	if [ "$i" -gt 60 ]; then
		nettact_err "clock still unset after 5 minutes; not starting (check NTP)"
		exit 1
	fi
	sleep 5
done

# 2. A usable network. The default route is what actually gates the first
#    connection; DNS follows it closely enough that one check covers both in
#    practice, and a wrong guess only costs one respawn.
i=0
while ! ip route show default 2>/dev/null | grep -q .; do
	i=$((i + 1))
	if [ "$i" -gt 60 ]; then
		nettact_err "no default route after 5 minutes; not starting"
		exit 1
	fi
	sleep 5
done

# 3. A binary. In ram mode this runs on every boot (/tmp is empty again); in
#    flash mode only the first time, or after a sysupgrade wiped it.
#
#    Pruning first is what makes a flash -> ram switch actually give the space
#    back: the mode change alone would leave the old ~11 MB copy on the overlay
#    forever, and freeing the overlay is the entire reason someone switches.
nettact_prune_stale_binary
if [ ! -x "$BIN" ]; then
	nettact_log "agent binary missing at $BIN; fetching"
	if ! /usr/lib/nettact/fetch.sh install; then
		nettact_err "could not obtain the agent binary; will retry"
		exit 1
	fi
	# Just downloaded, so it is by definition the version the source publishes.
	# Recording that here is what stops step 4 asking the same source the same
	# question a second time on every RAM-mode boot.
	nettact_mark_version_checked
else
	# 4. …and the RIGHT binary. Step 3 asks only whether one exists, which is
	#    correct as far as it goes and is why a router that installed the agent
	#    the day before a release kept running the old build: in ram mode until
	#    the next reboot, in flash mode indefinitely. When that build is old
	#    enough for the server to refuse its wire schema, the result is a respawn
	#    loop that no amount of restarting fixes.
	#
	#    Placed here, after the clock and the route, because both are
	#    preconditions for it: HTTPS to the download source needs a plausible
	#    year, and resolving a version with no default route is a guaranteed
	#    timeout. Placed in the `else` because the branch above already fetched.
	#
	#    It cannot fail this script. Every path inside returns 0 and leaves the
	#    binary that is already here to be exec'd below — that is what keeps a boot
	#    with no uplink a normal boot rather than a start-up failure — and it
	#    checks at most once every few hours, so the ten-second respawn loop
	#    cannot turn into a download loop against the mirror. The reasoning for
	#    both, and for what this deliberately does not do, is on the function.
	nettact_check_binary_version
fi

# exec, so the agent inherits this PID and procd supervises it directly. The
# environment procd set for us (NETTACT_AGENT_*) is what configures it.
exec "$BIN"
