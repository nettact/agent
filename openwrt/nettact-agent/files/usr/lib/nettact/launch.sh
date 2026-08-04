#!/bin/sh
# procd runs this, not the agent directly. It does the three things that must
# happen between "the router finished booting" and "the agent can work", then
# hands its own process over to the agent so procd keeps supervising the real
# thing rather than a wrapper.
#
# Failures here exit non-zero on purpose: procd's respawn is the retry loop, and
# an exit that lands in syslog is far easier to diagnose than a script that
# silently sleeps forever.
set -e

. /usr/lib/nettact/common.sh

BIN="$(nettact_bin)"

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
if [ ! -x "$BIN" ]; then
	nettact_log "agent binary missing at $BIN; fetching"
	if ! /usr/lib/nettact/fetch.sh install; then
		nettact_err "could not obtain the agent binary; will retry"
		exit 1
	fi
fi

# exec, so the agent inherits this PID and procd supervises it directly. The
# environment procd set for us (NETTACT_AGENT_*) is what configures it.
exec "$BIN"
