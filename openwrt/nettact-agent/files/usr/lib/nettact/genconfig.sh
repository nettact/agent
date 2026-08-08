#!/bin/sh
# Render the agent's YAML configuration from UCI.
#
#   genconfig.sh [render]   write /var/etc/nettact/agent.yaml (0600)
#   genconfig.sh print      write the same document to stdout, touching nothing
#
# Why a file at all, when every scalar setting also has a NETTACT_AGENT_*
# environment variable: `servers:` has no environment form. A list of records
# does not fit the one-key-one-variable model, so the only way a router can
# report to more than one server is a configuration file. Rendering the whole
# document — rather than a file for `servers:` and environment for the rest —
# keeps one answer to "where did this setting come from".
#
# The file lands on tmpfs (see NETTACT_GEN_CONFIG in common.sh), so the
# enrollment token does not come to rest on flash a second time and editing
# settings costs no overlay erase cycles.
#
# Only keys the user actually set are emitted. An omitted key means the agent's
# own default; an EMPTY key is a startup error by design, so "unset" must never
# render as `key: ''`.
#
# Validation is deliberately not duplicated here. The agent already checks every
# range, enum and mutual exclusion and reports them naming the setting, so a
# second implementation in shell could only drift.
. /usr/lib/nettact/common.sh

# Nothing here wants filename expansion, and one value definitely must not have
# it: `host:*.example.com` is a legal access selector, and an unquoted expansion
# of the list would replace it with whatever happens to sit in the working
# directory.
set -f

action="${1:-render}"

# --- output plumbing --------------------------------------------------------

case "$action" in
	print)
		out="$(mktemp)" || exit 1
		;;
	render)
		mkdir -p "$NETTACT_GEN_DIR" || exit 1
		chmod 0700 "$NETTACT_GEN_DIR" 2>/dev/null
		# Same directory as the destination so the install is a rename: nothing
		# can read a half-written config.
		out="$NETTACT_GEN_DIR/.agent.yaml.new"
		rm -f "$out"
		;;
	*)
		echo "usage: genconfig.sh [render|print]" >&2
		exit 2
		;;
esac
# shellcheck disable=SC2064
trap "rm -f '$out'" EXIT
: > "$out" || exit 1
chmod 0600 "$out" 2>/dev/null

emit() { printf '%s\n' "$*" >> "$out"; }

# --- value rendering --------------------------------------------------------

# yq renders a value as a single-quoted YAML scalar. Single quoting is the one
# YAML form with no escape sequences at all — the only special character is the
# quote itself, doubled — so an enrollment token, a URL with a #, or a host
# selector with a * all survive verbatim.
yq() {
	printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"
}

# put emits `key: value`, or nothing when the value is empty.
put() { # put <indent> <key> <value>
	[ -n "$3" ] || return 0
	emit "$1$2: $(yq "$3")"
}

# put_bool emits a YAML boolean only when the UCI flag is on. Off is the agent's
# default for every boolean here, so rendering `false` would add noise without
# changing behaviour.
put_bool() { # put_bool <indent> <key> <uci-value>
	case "$3" in
		1|true|yes|on) emit "$1$2: true" ;;
	esac
}

# put_bool_on is the mirror, for the one setting whose agent-side default is
# TRUE. Only an explicit off is rendered: emitting `true` would be noise, and
# omitting a `false` would silently turn the setting back on. An unset UCI option
# is an empty string and matches neither case, which is what "leave the agent's
# default alone" has to render as.
put_bool_on() { # put_bool_on <indent> <key> <uci-value>
	case "$3" in
		0|false|no|off) emit "$1$2: false" ;;
	esac
}

# put_int emits an UNQUOTED scalar, for the two settings the agent decodes as a
# number rather than a string. A quoted `'8'` is a YAML string and fails to
# unmarshal, so quoting these silently breaks every config that sets them.
#
# A value that is not a plain number is quoted instead, which keeps the document
# structurally valid — an unquoted value carrying a ':' or a '#' would corrupt
# the surrounding YAML. The agent still rejects it, but with "cannot unmarshal
# 'lots' into int" for that one key rather than a parse failure for the file.
put_int() { # put_int <indent> <key> <value>
	[ -n "$3" ] || return 0
	case "$3" in
		*[!0-9]*) put "$1" "$2" "$3" ;;
		*) emit "$1$2: $3" ;;
	esac
}

# put_list emits a YAML sequence from a space-separated UCI list.
put_list() { # put_list <indent> <key> <items>
	[ -n "$3" ] || return 0
	emit "$1$2:"
	for item in $3; do
		emit "$1  - $(yq "$item")"
	done
}

# --- permissions ------------------------------------------------------------

# The named permission presets, expanded here rather than in the LuCI page.
#
# UCI is the source of truth, so `permission_mode=host_metrics` has to mean the
# same thing whether the settings page wrote it or somebody typed it into
# /etc/config/nettact. A page that stored the expanded list instead would leave a
# hand-edited config silently granting something else.
#
# These lists ARE protocol/permission.Bundles(); openwrt/permcatalog_test.go
# reads them out of this file and fails if they drift. `default` (and its alias
# `recommended`) deliberately have no list: they are the agent's own built-in
# grant, so the correct rendering is to say nothing at all.
PERM_HOST_METRICS="probe.icmp probe.dns probe.http probe.tcp probe.nat
network.gateway.probe
network.interface.status.read network.interface.address.read
network.wifi.status.read
host.cpu.read host.memory.read host.disk.read host.load.read host.uptime.read
host.network.io.read host.temperature.read
diagnostic.traceroute.icmp diagnostic.traceroute.tcp"

PERM_FULL="probe.icmp probe.dns probe.http probe.http.extended probe.tcp probe.nat
network.gateway.probe
network.interface.status.read network.interface.address.read
network.wifi.status.read network.wifi.ssid.read
network.neighbor.read network.neighbor.hostname.read
host.cpu.read host.memory.read host.disk.read host.load.read host.uptime.read
host.network.io.read host.temperature.read
host.process.basic.read host.process.owner.read host.process.resource.read
host.process.io.read
host.connection.summary.read host.connection.local.read
host.connection.remote.read host.connection.owner.read
diagnostic.traceroute.icmp diagnostic.traceroute.tcp
game.process.detect game.performance.read game.gpu.read"

# GEN_ERROR is set when a setting cannot be rendered into anything meaningful.
# The document is thrown away rather than installed in that case: guessing at a
# permission grant could quietly collect more than the user asked for, which is
# the one failure here that must never be silent.
GEN_ERROR=

# emit_permissions renders one permission grant.
#
# `custom` with nothing selected renders as `none` rather than an empty list —
# the user asked for a hand-picked grant and picked nothing, which is "grant
# nothing"; the literal alternative (an empty value) is rejected at startup and
# would take the router down instead.
emit_permissions() { # emit_permissions <indent> <mode> <list>
	local list="$3"
	case "$2" in
		''|default|recommended)
			return 0
			;;
		none)
			emit "$1permissions: 'none'"
			return 0
			;;
		host_metrics)
			list="$PERM_HOST_METRICS"
			;;
		full)
			list="$PERM_FULL"
			;;
		custom)
			;;
		*)
			nettact_err "unknown permission_mode '$2' (use default, host_metrics, full, none or custom)"
			GEN_ERROR=1
			return 0
			;;
	esac
	if [ -z "$list" ]; then
		emit "$1permissions: 'none'"
	else
		put_list "$1" permissions "$list"
	fi
}

# --- probe access -----------------------------------------------------------

# emit_probe_access renders one target-access policy, or nothing when no mode is
# set (the agent's default: LAN and public allowed, loopback/link-local/metadata
# denied).
#
# The `none` denylist is emitted rather than omitted in denylist mode: the agent
# requires a denylist that is either non-empty or the literal `none`, so "deny
# nothing" has to be spelled out. An allowlist mode with nothing allowed is left
# to fail at startup with the agent's own message — silently substituting
# something here would mean quietly probing targets the user did not allow.
emit_probe_access() { # emit_probe_access <indent> <mode> <allow> <deny>
	[ -n "$2" ] || return 0
	emit "$1probe_access:"
	emit "$1  mode: $(yq "$2")"
	put_list "$1  " allowlist "$3"
	if [ -n "$4" ]; then
		put_list "$1  " denylist "$4"
	elif [ "$2" = denylist ]; then
		emit "$1  denylist: 'none'"
	fi
}

# --- servers ----------------------------------------------------------------

srv() { # srv <index> <option>
	uci -q get "nettact.@server[$1].$2" 2>/dev/null || true
}

# emit_servers renders the `servers:` list from the repeatable `config server`
# sections. Sections are addressed by type index, so both named and anonymous
# ones are picked up in file order — and that order is meaningful: the first
# entry is the one that would own frame capture on a platform that has it.
emit_servers() {
	local i=0 name url
	local any=0
	while [ -n "$(uci -q get "nettact.@server[$i]" 2>/dev/null || true)" ]; do
		name="$(srv "$i" name)"
		url="$(srv "$i" url)"
		# A nameless or address-less entry cannot be rendered into anything the
		# agent would accept, and emitting a partial one would fail the whole
		# start. Skipping it with a log line keeps the other servers working.
		if [ -z "$name" ] || [ -z "$url" ]; then
			nettact_err "server entry #$i has no name or no url; skipping it"
			i=$((i + 1))
			continue
		fi
		if [ "$any" = 0 ]; then
			emit "servers:"
			any=1
		fi
		emit "  - name: $(yq "$name")"
		emit "    url: $(yq "$url")"
		put "    " enroll_token "$(srv "$i" enroll_token)"
		put "    " enroll_token_file "$(srv "$i" enroll_token_file)"
		put_bool "    " tls_insecure "$(srv "$i" tls_insecure)"
		emit_permissions "    " "$(srv "$i" permission_mode)" "$(srv "$i" permissions)"
		emit_probe_access "    " \
			"$(srv "$i" probe_access_mode)" \
			"$(srv "$i" probe_allowlist)" \
			"$(srv "$i" probe_denylist)"
		i=$((i + 1))
	done
	return 0
}

# --- the document -----------------------------------------------------------

emit "# NetTact agent configuration — GENERATED from /etc/config/nettact."
emit "# Rewritten from UCI every time the service starts; edits here are lost."
emit "# To hand-write a configuration instead, create $NETTACT_USER_CONFIG:"
emit "# the init script then uses that file and generates nothing."
emit "#"
emit "# data_dir is not written here on purpose. It arrives as an environment"
emit "# variable, so a hand-written file that omits the key still keeps the"
emit "# agent's identity on flash at $NETTACT_DATA_DIR."
emit ""

# Server connection. The two spellings are mutually exclusive in the agent —
# a config carrying both has two answers for which server comes first — so the
# mode switch picks one and never renders a mixture.
if [ "$(nettact_cfg server_mode single)" = multi ]; then
	emit_servers
else
	put "" server_url "$(nettact_cfg server_url)"
	put "" enroll_token "$(nettact_cfg enroll_token)"
	put "" enroll_token_file "$(nettact_cfg enroll_token_file)"
	put_bool "" tls_insecure "$(nettact_cfg tls_insecure)"
fi

put "" upload_interval "$(nettact_cfg upload_interval)"
put "" wire_format "$(nettact_cfg wire_format)"

# Whether an unsent backlog is written to flash while a server is unreachable,
# and for how long after the disconnect. The UCI flag is persist_enable rather
# than persist because it is the one boolean here whose agent default is true, so
# the two spellings do NOT mean the same thing in the same way as elsewhere.
put_bool_on "" persist "$(nettact_cfg persist_enable)"
put "" persist_window "$(nettact_cfg persist_window)"

# The machine-wide grant. A server entry that names its own replaces this one.
emit_permissions "" "$(nettact_cfg permission_mode)" "$(nettact_cfg permissions)"

# The machine's target-access floor. A server entry can only narrow it.
emit_probe_access "" \
	"$(nettact_cfg probe_access_mode)" \
	"$(nettact_cfg probe_allowlist)" \
	"$(nettact_cfg probe_denylist)"

put "" min_probe_interval "$(nettact_cfg min_probe_interval)"
put_int "" max_probe_concurrency "$(nettact_cfg max_probe_concurrency)"
put "" snapshot_min_interval "$(nettact_cfg snapshot_min_interval)"
put "" snapshot_timeout "$(nettact_cfg snapshot_timeout)"
put_int "" max_trace_concurrency "$(nettact_cfg max_trace_concurrency)"

# --- install ----------------------------------------------------------------

# A setting we could not render is fatal rather than best-effort. The document is
# still complete apart from that one key, so installing it would start an agent
# whose collection policy is not the one the user configured — and nothing
# downstream could tell.
if [ -n "$GEN_ERROR" ]; then
	nettact_err "refusing to write $NETTACT_GEN_CONFIG from an unusable configuration"
	exit 1
fi

if [ "$action" = print ]; then
	cat "$out"
else
	mv -f "$out" "$NETTACT_GEN_CONFIG" || {
		nettact_err "cannot write $NETTACT_GEN_CONFIG"
		exit 1
	}
fi
trap - EXIT
rm -f "$out" 2>/dev/null
exit 0
