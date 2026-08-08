#!/bin/sh
# Nightly agent-binary update, run from cron when auto_update is on.
#
# This is the router's equivalent of the systemd timer / launchd job that
# `install.sh --auto-update` sets up on a Linux or macOS host: check the download
# source once a day, and if a newer binary is published, install it and restart
# the agent. The cron entry is written and removed by nettact_sync_cron (see
# common.sh), so this script's own job is to decide whether to act and to leave
# the service alone when nothing changed.
#
# It re-reads UCI rather than trusting the presence of the cron line, because
# those two can legitimately disagree for a minute: the setting is edited, the
# service has not been restarted yet, and the router should behave as the setting
# says. Every guard below is therefore repeated here, cheaply.
set -e

. /usr/lib/nettact/common.sh

[ "$(nettact_cfg enabled 0)" = 1 ] || exit 0
[ "$(nettact_cfg auto_update 0)" = 1 ] || exit 0

# A service somebody stopped by hand stays stopped. This is also what lets the
# init script leave the cron entry alone on stop (see nettact_sync_cron): without
# the check, tonight's update would start an agent its owner had just shut down.
/etc/init.d/nettact running >/dev/null 2>&1 || exit 0

# A pinned version means "stay on this one", and updating past it would be the
# opposite of what the pin is for. install.sh refuses --auto-update together with
# a pinned --version for the same reason; here the pin can be set afterwards, so
# it is enforced at run time instead of at install time.
version="$(nettact_cfg version latest)"
if [ -n "$version" ] && [ "$version" != latest ]; then
	nettact_log "automatic update skipped: version is pinned to $version"
	exit 0
fi

bin="$(nettact_bin)"

# The binary is identified by content, not by version string: fetch.sh already
# resolves 'latest', downloads and verifies the checksum, and leaves the existing
# file untouched when it is byte-identical. Comparing before and after is what
# tells us whether a restart is warranted — restarting an agent that did not
# change would drop its connection and its in-memory buffer for nothing.
before=""
[ -f "$bin" ] && before="$(sha256sum "$bin" | awk '{print $1}')"

if ! /usr/lib/nettact/fetch.sh install; then
	# Not an error worth escalating: the router may simply be offline right now,
	# and the next run is a day away — the agent keeps running on what it has.
	nettact_err "automatic update: could not fetch the agent binary (will try again tomorrow)"
	exit 0
fi

after=""
[ -f "$bin" ] && after="$(sha256sum "$bin" | awk '{print $1}')"

if [ -z "$after" ] || [ "$before" = "$after" ]; then
	exit 0
fi

nettact_log "automatic update: new agent binary installed, restarting the service"
/etc/init.d/nettact restart
