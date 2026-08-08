#!/bin/sh
# Offline checks for the OpenWrt shell components.
#
# The real thing needs a router; this covers the part most likely to be wrong
# without one — the architecture table, which decides WHICH binary a device
# downloads and whose failure mode (a mipsel box fetching a hardfloat build) is
# a boot loop rather than an error message.
#
# opkg and uci are stubbed, so this runs anywhere with a POSIX shell.
#
# One limitation worth stating: this runs on the developer's or CI runner's
# shell and coreutils, not BusyBox. Divergences between the two are invisible
# here — `tr -d '[:space:]'` deleting the literal characters of the class rather
# than whitespace is a real example that only a router caught — so a script that
# passes this still has to be run on a device once.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
STUB="$(mktemp -d)"
trap 'rm -rf "$STUB"' EXIT

fail=0
check() {
	want="$1" got="$2" what="$3"
	if [ "$want" = "$got" ]; then
		printf '  ok   %-28s -> %s\n' "$what" "$got"
	else
		printf '  FAIL %-28s -> %s (want %s)\n' "$what" "$got" "$want"
		fail=1
	fi
}

# --- stubs ------------------------------------------------------------------

cat > "$STUB/uci" <<'EOF'
#!/bin/sh
# Answers `uci -q get <key>` from the environment.
#
# T_UCI carries a whole config as newline-separated key=value lines, which is
# what the genconfig checks need; T_MODE/T_BASE/T_VERSION are the older
# single-option shorthands and still win when set.
[ "$1" = "-q" ] && shift
[ "$1" = "get" ] || exit 1
key="$2"

case "$key" in
	nettact.main.mode)          [ -n "${T_MODE:-}" ] && { printf '%s' "$T_MODE"; exit 0; } ;;
	nettact.main.download_base) [ -n "${T_BASE:-}" ] && { printf '%s' "$T_BASE"; exit 0; } ;;
	nettact.main.version)       [ -n "${T_VERSION:-}" ] && { printf '%s' "$T_VERSION"; exit 0; } ;;
esac

# The loop must not run in a subshell, or `found` never reaches this scope.
found=
while IFS= read -r line; do
	case "$line" in
		"$key="*) found="${line#*=}"; break ;;
	esac
done <<INNER
${T_UCI:-}
INNER
[ -n "$found" ] || exit 1
printf '%s' "$found"
exit 0
EOF

cat > "$STUB/opkg" <<'EOF'
#!/bin/sh
[ "$1" = "print-architecture" ] || exit 1
# Real opkg lists the generic entries first and the device's own arch last,
# which is why resolve_arch takes the last non-generic line.
echo "arch all 1"
echo "arch noarch 1"
[ -n "${T_ARCH:-}" ] && echo "arch $T_ARCH 10"
exit 0
EOF

cat > "$STUB/logger" <<'EOF'
#!/bin/sh
exit 0
EOF

chmod 0755 "$STUB"/*
PATH="$STUB:$PATH"
export PATH

# fetch.sh reads its helpers from the installed location, so point them at the
# working tree rather than copying the files around.
FETCH="$STUB/fetch.sh"
mkdir -p "$STUB/lib"
sed "s#^\. /usr/lib/nettact/common.sh#. $HERE/nettact-agent/files/usr/lib/nettact/common.sh#" \
	"$HERE/nettact-agent/files/usr/lib/nettact/fetch.sh" > "$FETCH"
chmod 0755 "$FETCH"

# --- architecture table -----------------------------------------------------

echo "architecture mapping:"
for pair in \
	"x86_64 amd64" \
	"i386_pentium4 386" \
	"aarch64_cortex-a53 arm64" \
	"aarch64_generic arm64" \
	"arm_cortex-a7_neon-vfpv4 armv7" \
	"arm_cortex-a9_vfpv3-d16 armv7" \
	"arm_cortex-a15_neon-vfpv4 armv7" \
	"arm_arm1176jzf-s_vfp armv6" \
	"arm_mpcore armv6" \
	"arm_arm926ej-s armv5" \
	"arm_fa526 armv5" \
	"arm_xscale armv5" \
	"arm_cortex-a53 armv7" \
	"arm_cortex-a53_neon-vfpv4 armv7" \
	"arm_cortex-a72 armv7" \
	"arm_cortex-a17 armv7" \
	"mipsel_24kc mipsle-softfloat" \
	"mipsel_74kc mipsle-softfloat" \
	"mipsel_mips32 mipsle-softfloat" \
	"mips_24kc mips-softfloat" \
	"mips_4kec mips-softfloat" \
	"riscv64_riscv64 riscv64"
do
	set -- $pair
	got="$(T_ARCH="$1" "$FETCH" arch 2>/dev/null || echo ERROR)"
	check "$2" "$got" "$1"
done

# An architecture with no build must say so rather than guessing.
got="$(T_ARCH="powerpc_8548" "$FETCH" arch 2>/dev/null || echo ERROR)"
check "ERROR" "$got" "powerpc_8548 (unsupported)"

# --- version resolution -----------------------------------------------------

echo "version resolution:"
got="$(T_ARCH=x86_64 T_VERSION=v1.2.3 "$FETCH" resolve 2>/dev/null || echo ERROR)"
check "v1.2.3" "$got" "pinned version"

got="$(T_ARCH=x86_64 T_VERSION=v9.9.9 "$FETCH" resolve v0.4.2 2>/dev/null || echo ERROR)"
check "v0.4.2" "$got" "explicit argument wins"

# --- mode / paths -----------------------------------------------------------

echo "storage mode:"
. "$HERE/nettact-agent/files/usr/lib/nettact/common.sh"
check "/tmp/nettact/nettact-agent" "$(T_MODE=ram nettact_bin)" "ram mode binary path"
check "/usr/lib/nettact/nettact-agent" "$(T_MODE=flash nettact_bin)" "flash mode binary path"
check "ram" "$(T_MODE=nonsense nettact_mode)" "unknown mode falls back to ram"
check "/etc/nettact/data" "$NETTACT_DATA_DIR" "identity stays on flash"

# --- stale-binary pruning ----------------------------------------------------
#
# Switching from flash to ram is something people do BECAUSE the overlay is
# full, so leaving the old ~11 MB copy behind defeats the entire point. The
# other half of this is just as important: the flash directory also holds the
# package's own scripts, so the prune must take two files and nothing else.

echo "stale binary pruning:"

# A `VAR=x func` prefix persists after the call in some shells, so the earlier
# T_MODE cases could still be in scope here and would answer the mode lookup
# ahead of T_UCI. Clear it, and drive these cases through T_UCI alone.
unset T_MODE 2>/dev/null || true
T_UCI=""
export T_UCI

PRUNE="$STUB/flashdir"
NETTACT_FLASH_DIR="$PRUNE"

reset_flashdir() {
	rm -rf "$PRUNE"
	mkdir -p "$PRUNE"
	: > "$PRUNE/nettact-agent"
	: > "$PRUNE/.nettact-agent.download"
	: > "$PRUNE/common.sh"
	: > "$PRUNE/launch.sh"
	: > "$PRUNE/fetch.sh"
	: > "$PRUNE/genconfig.sh"
}

reset_flashdir
T_UCI="nettact.main.mode=flash"
nettact_prune_stale_binary
[ -f "$PRUNE/nettact-agent" ] \
	&& printf '  ok   %-28s -> kept\n' "flash mode: binary" \
	|| { printf '  FAIL %-28s -> deleted\n' "flash mode: binary"; fail=1; }

reset_flashdir
T_UCI="nettact.main.mode=ram"
nettact_prune_stale_binary
[ -f "$PRUNE/nettact-agent" ] \
	&& { printf '  FAIL %-28s -> kept\n' "ram mode: binary"; fail=1; } \
	|| printf '  ok   %-28s -> deleted\n' "ram mode: binary"
[ -f "$PRUNE/.nettact-agent.download" ] \
	&& { printf '  FAIL %-28s -> kept\n' "ram mode: partial download"; fail=1; } \
	|| printf '  ok   %-28s -> deleted\n' "ram mode: partial download"
for keep in common.sh launch.sh fetch.sh genconfig.sh; do
	[ -f "$PRUNE/$keep" ] \
		&& printf '  ok   %-28s -> kept\n' "ram mode: $keep" \
		|| { printf '  FAIL %-28s -> DELETED\n' "ram mode: $keep"; fail=1; }
done

# Nothing to prune must not be an error: launch.sh runs this on every start.
rm -f "$PRUNE/nettact-agent" "$PRUNE/.nettact-agent.download"
if nettact_prune_stale_binary; then
	printf '  ok   %-28s -> succeeds\n' "ram mode: nothing to prune"
else
	printf '  FAIL %-28s -> non-zero exit\n' "ram mode: nothing to prune"; fail=1
fi

NETTACT_FLASH_DIR=/usr/lib/nettact
T_UCI=""

# --- generated agent configuration -------------------------------------------
#
# genconfig.sh renders /var/etc/nettact/agent.yaml from UCI. Two of its rules can
# take a router off the air if they break, and neither shows up until the agent
# refuses to start: `servers:` and `server_url:` are mutually exclusive, and an
# "unset" option must be omitted rather than rendered as an empty value.

echo "generated configuration:"

GEN="$STUB/genconfig.sh"
sed "s#^\. /usr/lib/nettact/common.sh#. $HERE/nettact-agent/files/usr/lib/nettact/common.sh#" \
	"$HERE/nettact-agent/files/usr/lib/nettact/genconfig.sh" > "$GEN"
chmod 0755 "$GEN"

# gen <what> <config> — render and stash the document in $GENOUT.
gen() {
	GENOUT="$(T_UCI="$2" "$GEN" print 2>/dev/null || echo 'RENDER FAILED')"
}

has() { # has <label> <line>
	case "
$GENOUT" in
		*"
$2"*) printf '  ok   %-28s -> %s\n' "$1" "$2" ;;
		*) printf '  FAIL %-28s -> missing: %s\n' "$1" "$2"; fail=1 ;;
	esac
}

hasnt() { # hasnt <label> <substring>
	case "$GENOUT" in
		*"$2"*) printf '  FAIL %-28s -> present: %s\n' "$1" "$2"; fail=1 ;;
		*) printf '  ok   %-28s -> absent: %s\n' "$1" "$2" ;;
	esac
}

gen single 'nettact.main.server_url=https://a.example.com
nettact.main.enroll_token=tok123'
has "single.server_url" "server_url: 'https://a.example.com'"
has "single.enroll_token" "enroll_token: 'tok123'"
hasnt "single.no servers list" "servers:"
# An unset boolean must not render at all: false is already the agent's default,
# and an empty value would be a startup error rather than a default.
hasnt "single.tls off is omitted" "tls_insecure:"
hasnt "single.no empty values" ": ''"

gen tls 'nettact.main.server_url=https://a.example.com
nettact.main.tls_insecure=1'
has "single.tls on" "tls_insecure: true"

# A quote in a token must survive as data, not end the YAML scalar early.
gen quoting "nettact.main.server_url=https://a.example.com
nettact.main.enroll_token=it's"
has "quoting.doubled" "enroll_token: 'it''s'"

# permission_mode: default means "say nothing and let the agent use its own".
gen perm-default 'nettact.main.server_url=https://a.example.com
nettact.main.permission_mode=default
nettact.main.permissions=probe.icmp probe.dns'
hasnt "perm.default omits the key" "permissions:"

gen perm-none 'nettact.main.server_url=https://a.example.com
nettact.main.permission_mode=none'
has "perm.none" "permissions: 'none'"

# The named presets. These are the ones that silently did nothing before: the
# settings page stores the preset NAME, so a mode without a branch here renders
# no `permissions:` key at all — which reads as the agent's built-in grant, not
# as an error. The full lists are checked against protocol/permission.Bundles()
# by openwrt/permcatalog_test.go; here we only prove the branch fires.
gen perm-host-metrics 'nettact.main.server_url=https://a.example.com
nettact.main.permission_mode=host_metrics'
has "perm.host_metrics expands" "permissions:"
has "perm.host_metrics cpu" "  - 'host.cpu.read'"
has "perm.host_metrics temp" "  - 'host.temperature.read'"
has "perm.host_metrics keeps base" "  - 'probe.icmp'"
hasnt "perm.host_metrics no process" "host.process.basic.read"

gen perm-full 'nettact.main.server_url=https://a.example.com
nettact.main.permission_mode=full'
has "perm.full expands" "  - 'host.process.basic.read'"
has "perm.full game" "  - 'game.gpu.read'"

# `default` and its alias mean the agent's own built-in grant, which is what
# saying nothing produces.
gen perm-recommended 'nettact.main.server_url=https://a.example.com
nettact.main.permission_mode=recommended'
hasnt "perm.recommended omits key" "permissions:"

# An unrecognised mode must NOT fall through to the default grant: we would be
# collecting something the user did not ask for and nothing would say so.
# Capture the status through a `||` list — a bare failing assignment would trip
# `set -e` and silently end the whole run here.
GENOUT="$(T_UCI='nettact.main.server_url=https://a.example.com
nettact.main.permission_mode=nonee' "$GEN" print 2>/dev/null)" && rc=0 || rc=$?
if [ "$rc" != 0 ] && [ -z "$GENOUT" ]; then
	printf '  ok   %-28s -> refuses to render\n' "perm.unknown mode"
else
	printf '  FAIL %-28s -> rendered anyway (rc=%s)\n' "perm.unknown mode" "$rc"; fail=1
fi

gen perm-custom 'nettact.main.server_url=https://a.example.com
nettact.main.permission_mode=custom
nettact.main.permissions=probe.icmp probe.http'
has "perm.custom key" "permissions:"
has "perm.custom item 1" "  - 'probe.icmp'"
has "perm.custom item 2" "  - 'probe.http'"

# Custom with nothing picked means "grant nothing". Rendering an empty list
# instead would be rejected at startup and take the router down.
gen perm-custom-empty 'nettact.main.server_url=https://a.example.com
nettact.main.permission_mode=custom'
has "perm.custom empty" "permissions: 'none'"

gen access-default 'nettact.main.server_url=https://a.example.com'
hasnt "access.unset omits group" "probe_access:"

gen access-allow 'nettact.main.server_url=https://a.example.com
nettact.main.probe_access_mode=allowlist
nettact.main.probe_allowlist=scope:lan host:*.example.com'
has "access.mode" "  mode: 'allowlist'"
has "access.allow item" "    - 'scope:lan'"
# A selector with a glob must reach the file verbatim rather than being expanded
# against whatever happens to be in the working directory.
has "access.glob survives" "    - 'host:*.example.com'"
hasnt "access.no denylist" "denylist:"

# Denylist mode with nothing denied has to be spelled out; the agent rejects an
# empty denylist but accepts the literal `none`.
gen access-deny-none 'nettact.main.server_url=https://a.example.com
nettact.main.probe_access_mode=denylist'
has "access.deny none" "  denylist: 'none'"

gen limits 'nettact.main.server_url=https://a.example.com
nettact.main.upload_interval=15s
nettact.main.wire_format=json
nettact.main.min_probe_interval=2s
nettact.main.max_probe_concurrency=8
nettact.main.snapshot_min_interval=5s
nettact.main.snapshot_timeout=20s
nettact.main.max_trace_concurrency=2'
has "limits.upload" "upload_interval: '15s'"
has "limits.wire" "wire_format: 'json'"
has "limits.min probe" "min_probe_interval: '2s'"
has "limits.probe concurrency" "max_probe_concurrency: 8"
has "limits.snapshot interval" "snapshot_min_interval: '5s'"
has "limits.snapshot timeout" "snapshot_timeout: '20s'"
has "limits.trace concurrency" "max_trace_concurrency: 2"

# The two numeric settings decode as int, not string. Quoting them makes every
# config that sets one fail to unmarshal.
hasnt "limits.probe count unquoted" "max_probe_concurrency: '"
hasnt "limits.trace count unquoted" "max_trace_concurrency: '"

# A value that is not a number is quoted instead, so a ':' or '#' in it cannot
# corrupt the surrounding document; the agent then rejects that one key.
gen limits-bad 'nettact.main.server_url=https://a.example.com
nettact.main.max_probe_concurrency=lots'
has "limits.bad int stays quoted" "max_probe_concurrency: 'lots'"

# Backlog persistence. This is the one boolean whose agent-side default is TRUE,
# so its rendering is inverted: an unset or enabled flag must emit nothing, and
# only an explicit off may be written. Emitting `persist: true` would be noise;
# failing to emit `persist: false` would silently turn back on a setting the
# router's owner switched off to spare their flash.
gen persist-default 'nettact.main.server_url=https://a.example.com'
hasnt "persist.unset omits key" "persist:"

gen persist-on 'nettact.main.server_url=https://a.example.com
nettact.main.persist_enable=1'
hasnt "persist.on omits key" "persist:"

gen persist-off 'nettact.main.server_url=https://a.example.com
nettact.main.persist_enable=0'
has "persist.off is rendered" "persist: false"

gen persist-window 'nettact.main.server_url=https://a.example.com
nettact.main.persist_window=10m'
has "persist.window" "persist_window: '10m'"

# Multi-server. The single-server keys must be entirely absent: the agent treats
# a config carrying both as an error, not a merge.
gen multi 'nettact.main.server_mode=multi
nettact.main.server_url=https://ignored.example.com
nettact.main.enroll_token=ignored
nettact.@server[0]=server
nettact.@server[0].name=home
nettact.@server[0].url=https://home.example.com
nettact.@server[0].enroll_token=htok
nettact.@server[1]=server
nettact.@server[1].name=work
nettact.@server[1].url=https://work.example.com
nettact.@server[1].tls_insecure=1
nettact.@server[1].permission_mode=custom
nettact.@server[1].permissions=probe.icmp
nettact.@server[1].probe_access_mode=allowlist
nettact.@server[1].probe_allowlist=cidr:10.0.0.0/8'
has "multi.list" "servers:"
has "multi.first name" "  - name: 'home'"
has "multi.first url" "    url: 'https://home.example.com'"
has "multi.first token" "    enroll_token: 'htok'"
has "multi.second name" "  - name: 'work'"
has "multi.second tls" "    tls_insecure: true"
has "multi.second perms" "      - 'probe.icmp'"
has "multi.second access" "      mode: 'allowlist'"
has "multi.second allow" "        - 'cidr:10.0.0.0/8'"
hasnt "multi.no server_url" "server_url:"
hasnt "multi.no top token" "enroll_token: 'ignored'"

# An entry with no url cannot be rendered into anything the agent accepts.
# Skipping it keeps the other servers working instead of failing the whole start.
gen multi-partial 'nettact.main.server_mode=multi
nettact.@server[0]=server
nettact.@server[0].name=broken
nettact.@server[1]=server
nettact.@server[1].name=good
nettact.@server[1].url=https://good.example.com'
has "multi.skips broken entry" "  - name: 'good'"
hasnt "multi.broken not rendered" "'broken'"

# --- rpcd status backend ---------------------------------------------------
#
# The log array is built by a shell loop, and getting that wrong is invisible:
# in ash every stage of a pipeline is its own subshell, so a `logread | while
# read` loop would accumulate the array in a child and the parent would emit an
# empty one. The LuCI panel just stays blank, with no error anywhere.

echo "rpcd status:"

# rpcd derives the ubus object name from the *file name* of the shell script in
# /usr/libexec/rpcd — no "luci." is prepended (that only happens for ucode
# plugins under /usr/share/rpcd/ucode). So the script must literally be named
# after the object the views call, or every RPC fails with -32000 "Object not
# found" while the script itself tests perfectly fine in isolation. That is the
# exact bug this guards: the script was once named "nettact" while the ACL and
# both views asked for "luci.nettact". Checked before anything reads the file,
# so a mismatch reports itself rather than surfacing as a sed error.
obj="luci.nettact"
rpcd_src="$HERE/luci-app-nettact/files/usr/libexec/rpcd/$obj"
if [ -f "$rpcd_src" ]; then
	printf '  ok   %-28s -> script named %s\n' "ubus.object" "$obj"
else
	printf '  FAIL %-28s -> no rpcd/%s (object name mismatch)\n' "ubus.object" "$obj"
	exit 1
fi

cat > "$STUB/jshn.sh" <<'EOF'
# Enough of jshn to observe what the CURRENT shell accumulated.
json_init() { J_KEYS=""; J_LOG_N=0; J_IN_LOG=""; }
json_add_boolean() { J_KEYS="$J_KEYS $1"; }
json_add_int() { J_KEYS="$J_KEYS $1"; }
json_add_string() {
	if [ -n "$J_IN_LOG" ]; then
		J_LOG_N=$((J_LOG_N + 1))
	else
		J_KEYS="$J_KEYS $1"
	fi
}
json_add_array() { J_KEYS="$J_KEYS $1"; [ "$1" = log ] && J_IN_LOG=1; }
json_close_array() { J_IN_LOG=""; }
json_add_object() { J_KEYS="$J_KEYS $1"; }
json_close_object() { :; }
json_load() { :; }
json_get_var() { :; }
json_dump() { echo "keys:$J_KEYS log_entries:$J_LOG_N"; }
EOF

cat > "$STUB/logread" <<'EOF'
#!/bin/sh
# A line with a glob character is included on purpose: unquoted word splitting
# must not expand it against the working directory.
printf 'daemon.info nettact: started\ndaemon.err nettact: probe * failed\ndaemon.info nettact: uploaded\n'
EOF

cat > "$STUB/ubus" <<'EOF'
#!/bin/sh
echo '{"nettact":{"instances":{"nettact":{"running":true}}}}'
EOF

cat > "$STUB/logger" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0755 "$STUB/logread" "$STUB/ubus" "$STUB/logger"

RPCD="$STUB/rpcd-nettact"
sed -e "s#^\. /usr/share/libubox/jshn.sh#. $STUB/jshn.sh#" \
    -e "s#^\. /usr/lib/nettact/common.sh#. $HERE/nettact-agent/files/usr/lib/nettact/common.sh#" \
    "$rpcd_src" > "$RPCD"
chmod 0755 "$RPCD"

out="$(T_ARCH=x86_64 "$RPCD" call status </dev/null 2>/dev/null || echo 'ERROR')"
got="$(printf '%s' "$out" | sed -n 's/.*log_entries:\([0-9]*\).*/\1/p')"
check "3" "${got:-0}" "status returns the log lines"

for key in running enabled enrolled binary_present mode config_source config_path now log; do
	case " $out " in
		*" $key"*) printf '  ok   %-28s -> present\n' "status.$key" ;;
		*) printf '  FAIL %-28s -> missing\n' "status.$key"; fail=1 ;;
	esac
done

# The agent's connection status is passed through only when the agent wrote one
# AND the process that wrote it is still alive. All three cases matter: a missing
# file must not produce an empty agent_status the view would try to parse; a live
# one must actually reach the page — that is the whole difference between "the
# service is running" and "the server rejected our certificate"; and a document
# from a process that is gone must be dropped, because procd reports the
# respawned launch.sh as running for minutes before a new agent writes anything.
STATUS_STUB="$STUB/status.json"
rm -f "$STATUS_STUB"
out="$(T_ARCH=x86_64 NETTACT_STATUS_FILE="$STATUS_STUB" "$RPCD" call status </dev/null 2>/dev/null || echo 'ERROR')"
case " $out " in
	*" agent_status"*) printf '  FAIL %-28s -> present with no status file\n' "status.agent_status"; fail=1 ;;
	*) printf '  ok   %-28s -> absent with no status file\n' "status.agent_status" ;;
esac

# $$ is this script: a pid that is certainly alive.
printf '{"schema":1,"pid":%d,"servers":[{"name":"default","state":"connected"}]}\n' "$$" > "$STATUS_STUB"
out="$(T_ARCH=x86_64 NETTACT_STATUS_FILE="$STATUS_STUB" "$RPCD" call status </dev/null 2>/dev/null || echo 'ERROR')"
case " $out " in
	*" agent_status"*) printf '  ok   %-28s -> passed through for a live pid\n' "status.agent_status" ;;
	*) printf '  FAIL %-28s -> not passed through for a live pid\n' "status.agent_status"; fail=1 ;;
esac

# A reaped child's pid: Linux hands pids out in increasing order, so the one we
# just waited on is not about to come back as something else.
sh -c 'exit 0' & dead_pid=$!
wait "$dead_pid" 2>/dev/null || true
printf '{"schema":1,"pid":%d,"servers":[{"name":"default","state":"connected"}]}\n' "$dead_pid" > "$STATUS_STUB"
out="$(T_ARCH=x86_64 NETTACT_STATUS_FILE="$STATUS_STUB" "$RPCD" call status </dev/null 2>/dev/null || echo 'ERROR')"
case " $out " in
	*" agent_status"*) printf '  FAIL %-28s -> stale status from a dead pid passed through\n' "status.agent_status"; fail=1 ;;
	*) printf '  ok   %-28s -> dropped for a dead pid\n' "status.agent_status" ;;
esac

# A document with no pid at all cannot be attributed to a process, so it is not
# status either.
printf '{"schema":1,"servers":[{"name":"default","state":"connected"}]}\n' > "$STATUS_STUB"
out="$(T_ARCH=x86_64 NETTACT_STATUS_FILE="$STATUS_STUB" "$RPCD" call status </dev/null 2>/dev/null || echo 'ERROR')"
case " $out " in
	*" agent_status"*) printf '  FAIL %-28s -> pid-less document passed through\n' "status.agent_status"; fail=1 ;;
	*) printf '  ok   %-28s -> dropped when it names no pid\n' "status.agent_status" ;;
esac
rm -f "$STATUS_STUB"

# launch.sh must clear the previous process's file before it starts waiting, or
# the status page shows a dead agent's last state for as long as the clock and
# binary waits take.
if grep -q 'rm -f "$NETTACT_STATUS_FILE"' "$HERE/nettact-agent/files/usr/lib/nettact/launch.sh"; then
	printf '  ok   %-28s -> clears the stale status file\n' "launch.status"
else
	printf '  FAIL %-28s -> does not clear the stale status file\n' "launch.status"; fail=1
fi

# The methods the views call must all be listed, or ubus rejects them.
listed="$("$RPCD" list </dev/null 2>/dev/null || true)"
for m in status versions fetch fetch_status service; do
	case "$listed" in
		*"$m"*) printf '  ok   %-28s -> listed\n' "ubus.$m" ;;
		*) printf '  FAIL %-28s -> not listed\n' "ubus.$m"; fail=1 ;;
	esac
done

# And the ACL must grant every one of them, or the page loads and every button
# fails with a permission error.
acl="$HERE/luci-app-nettact/files/usr/share/rpcd/acl.d/luci-app-nettact.json"
for m in status versions fetch fetch_status service; do
	if grep -q "\"$m\"" "$acl"; then
		printf '  ok   %-28s -> granted\n' "acl.$m"
	else
		printf '  FAIL %-28s -> not granted\n' "acl.$m"; fail=1
	fi
done

# Both callers must ask for that same object name.
for f in "$acl" "$HERE"/luci-app-nettact/files/www/luci-static/resources/view/nettact/*.js; do
	if grep -q "$obj" "$f"; then
		printf '  ok   %-28s -> calls %s\n' "obj.$(basename "$f")" "$obj"
	else
		printf '  FAIL %-28s -> does not reference %s\n' "obj.$(basename "$f")" "$obj"; fail=1
	fi
done

# --- package lifecycle -------------------------------------------------------
#
# opkg runs prerm for an upgrade as well as a removal, telling them apart only
# by the first argument. Getting that wrong is silent and expensive: `opkg
# upgrade` would disable the service and delete the downloaded binary, and
# monitoring would simply stop until somebody noticed.

echo "package lifecycle:"

LIFE="$STUB/life"
mkdir -p "$LIFE/etc/init.d" "$LIFE/etc/rc.d" "$LIFE/usr/lib/nettact" "$LIFE/tmp"

# run_prerm <arg...> — runs prerm against a fake root and reports what it did.
run_prerm() {
	rm -rf "$LIFE"
	mkdir -p "$LIFE/bin" "$LIFE/usr/lib/nettact" "$LIFE/tmp/nettact"
	: > "$LIFE/usr/lib/nettact/nettact-agent"
	: > "$LIFE/actions"
	cat > "$LIFE/bin/nettact-init" <<EOF
#!/bin/sh
echo "\$1" >> "$LIFE/actions"
EOF
	chmod 0755 "$LIFE/bin/nettact-init"
	# Redirect the script's absolute paths at the fake root.
	sed -e "s#/etc/init.d/nettact#$LIFE/bin/nettact-init#g" \
	    -e "s#/usr/lib/nettact/nettact-agent#$LIFE/usr/lib/nettact/nettact-agent#g" \
	    -e "s#rm -rf /tmp/nettact#rm -rf $LIFE/tmp/nettact#g" \
	    "$HERE/nettact-agent/control/prerm" > "$LIFE/prerm"
	sh "$LIFE/prerm" "$@" >/dev/null 2>&1
}

run_prerm upgrade 1.2.3
check "" "$(cat "$LIFE/actions" 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')" "upgrade: no stop/disable"
[ -f "$LIFE/usr/lib/nettact/nettact-agent" ] \
	&& printf '  ok   %-28s -> kept\n' "upgrade: binary" \
	|| { printf '  FAIL %-28s -> deleted\n' "upgrade: binary"; fail=1; }

run_prerm remove
check "stop disable" "$(cat "$LIFE/actions" 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')" "remove: stops and disables"
[ -f "$LIFE/usr/lib/nettact/nettact-agent" ] \
	&& { printf '  FAIL %-28s -> kept\n' "remove: binary"; fail=1; } \
	|| printf '  ok   %-28s -> deleted\n' "remove: binary"

# An argument nobody anticipated must clean up rather than silently keep state.
run_prerm something-new
check "stop disable" "$(cat "$LIFE/actions" 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')" "unknown arg: cleans up"

# --- one-command installer ---------------------------------------------------
#
# install.sh is what the console hands a router owner, so its mistakes are made
# by someone who cannot read a shell script to find out what happened. Three of
# these are worth having offline in particular: a permission list that ACCUMULATES
# across runs would quietly widen a grant nobody widened; forcing enabled=1 before
# the server is written would make an install phone home mid-configuration; and
# "connected" being read from a status file left behind by a dead process would
# report success for a router that is in a respawn loop.

echo "one-command installer:"

INST="$STUB/inst"
mkdir -p "$INST/bin" "$INST/etc/nettact/data" "$INST/tmp"

# A recording uci: state as key=value lines (repeated keys are a list), plus a
# log of every subcommand so ordering can be asserted.
cat > "$INST/bin/uci" <<EOF
#!/bin/sh
S="$INST/uci.state"
L="$INST/uci.log"
[ "\$1" = "-q" ] && shift
cmd="\$1"; shift
printf '%s %s\n' "\$cmd" "\$*" >> "\$L"
case "\$cmd" in
	get)
		v="\$(sed -n "s/^\$1=//p" "\$S" 2>/dev/null | tail -n 1)"
		[ -n "\$v" ] || exit 1
		printf '%s\n' "\$v" ;;
	set)
		k="\${1%%=*}"; v="\${1#*=}"
		[ -f "\$S" ] && sed -i "/^\$k=/d" "\$S"
		printf '%s=%s\n' "\$k" "\$v" >> "\$S" ;;
	add_list)
		k="\${1%%=*}"; v="\${1#*=}"
		printf '%s=%s\n' "\$k" "\$v" >> "\$S" ;;
	delete)
		grep -q "^\$1=" "\$S" 2>/dev/null || exit 1
		sed -i "/^\$1=/d" "\$S" ;;
	commit) ;;
esac
exit 0
EOF

cat > "$INST/bin/opkg" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "$INST/opkg.log"
case "\$1" in
	list-installed) exit 0 ;;
	install) [ -n "\${T_OPKG_FAIL:-}" ] && exit 1 ;;
esac
exit 0
EOF

cat > "$INST/bin/nettact-init" <<EOF
#!/bin/sh
printf '%s\n' "\$1" >> "$INST/init.log"
[ "\$1" = status ] && echo "\${T_SERVICE_STATE:-running}"
exit 0
EOF

# Root is asserted, not assumed, so the test has to answer for it.
cat > "$INST/bin/id" <<'EOF'
#!/bin/sh
[ "$1" = "-u" ] && echo 0
exit 0
EOF

cat > "$INST/bin/logread" <<'EOF'
#!/bin/sh
exit 0
EOF

# Just the one query install.sh makes. The real jsonfilter is OpenWrt base
# system; this keeps the credential check testable off a router.
cat > "$INST/bin/jsonfilter" <<'EOF'
#!/bin/sh
file=""; expr=""
while [ $# -gt 0 ]; do
	case "$1" in
		-i) file="$2"; shift 2 ;;
		-e) expr="$2"; shift 2 ;;
		*) shift ;;
	esac
done
[ "$expr" = '@.servers.default.agent_token' ] || exit 1
tr -d ' \n\t' < "$file" 2>/dev/null \
	| sed -n 's/.*"default":{[^}]*"agent_token":"\([^"]*\)".*/\1/p'
EOF

# The real common.sh, then the paths moved onto the fake root. Sourcing the real
# file rather than restating it means install.sh keeps being tested against the
# same variable names the package actually defines.
cat > "$INST/common.sh" <<EOF
. $HERE/nettact-agent/files/usr/lib/nettact/common.sh
NETTACT_CONF_DIR="$INST/etc/nettact"
NETTACT_DATA_DIR="$INST/etc/nettact/data"
NETTACT_FLASH_DIR="$INST/usr/lib/nettact"
NETTACT_RAM_DIR="$INST/tmp/nettact"
NETTACT_STATUS_FILE="$INST/tmp/status.json"
NETTACT_GEN_CONFIG="$INST/var/etc/nettact/agent.yaml"
EOF

INSTALLER="$INST/install.sh"
# DATA_DIR is rewritten too: the installer checks for a saved credential BEFORE
# it installs the package that would define NETTACT_DATA_DIR, so it carries its
# own copy of that path and the fake root has to reach it.
sed -e "s#^\. /usr/lib/nettact/common.sh#. $INST/common.sh#" \
    -e "s#^DATA_DIR=/etc/nettact/data#DATA_DIR=$INST/etc/nettact/data#" \
    -e "s#/etc/init.d/nettact#$INST/bin/nettact-init#g" \
    "$HERE/install.sh" > "$INSTALLER"
chmod 0755 "$INSTALLER" "$INST/bin"/*

# run_install [args...] — a clean run against the fake root; exit status kept.
run_install() {
	rm -f "$INST/uci.state" "$INST/uci.log" "$INST/opkg.log" "$INST/init.log"
	PATH="$INST/bin:$PATH" sh "$INSTALLER" "$@" >"$INST/out" 2>&1
}

# rerun_install — same, keeping whatever state the previous run left.
rerun_install() {
	rm -f "$INST/opkg.log" "$INST/init.log"
	PATH="$INST/bin:$PATH" sh "$INSTALLER" "$@" >"$INST/out" 2>&1
}

ucival() { sed -n "s/^nettact\.main\.$1=//p" "$INST/uci.state" 2>/dev/null | tr '\n' ' ' | sed 's/ *$//'; }

# Refusals. Each of these would otherwise be discovered by the agent at startup,
# on a router whose owner is looking at a LuCI page that says "not running".
run_install --wait 0 && check "exit!=0" "exit=0" "no --server-url" \
	|| printf '  ok   %-28s -> refused\n' "no --server-url"
run_install --server-url http://s:1 --token t --mode bogus --wait 0 && check "exit!=0" "exit=0" "bad --mode" \
	|| printf '  ok   %-28s -> refused\n' "bad --mode"
run_install --server-url http://s:1 --token t --permissions '*' --wait 0 && check "exit!=0" "exit=0" "wildcard permissions" \
	|| printf '  ok   %-28s -> refused\n' "wildcard permissions"
run_install --server-url http://s:1 --token t --permissions ',,,' --wait 0 && check "exit!=0" "exit=0" "empty permission list" \
	|| printf '  ok   %-28s -> refused\n' "empty permission list"
run_install --server-url http://s:1 --token t --token-file /dev/null --wait 0 && check "exit!=0" "exit=0" "token and token-file" \
	|| printf '  ok   %-28s -> refused\n' "token and token-file"

# No token and no saved credential cannot enroll; no token WITH one is the
# ordinary re-run, and must not be turned into an error.
rm -f "$INST/etc/nettact/data/agent.json"
run_install --server-url http://s:1 --wait 0 && check "exit!=0" "exit=0" "no token, not enrolled" \
	|| printf '  ok   %-28s -> refused\n' "no token, not enrolled"
# …and refused before anything is installed. Reaching that verdict after two
# opkg installs leaves a fresh router carrying packages it never got to use.
check "0" "$(grep -c '\.ipk' "$INST/opkg.log" 2>/dev/null || echo 0)" "refusal installs nothing"

# A credential file is not the same thing as a credential for THIS install.
# Single mode enrolls under the name `default`; a router coming off multi-server
# mode has entries named after its servers and nothing under `default`, so
# accepting it would produce a config the agent cannot enroll with at all.
printf '{"v":2}' > "$INST/etc/nettact/data/agent.json"
run_install --server-url http://s:1 --wait 0 && check "exit!=0" "exit=0" "no token, credential-less file" \
	|| printf '  ok   %-28s -> refused\n' "no token, credential-less file"

cat > "$INST/etc/nettact/data/agent.json" <<'EOF'
{"v":2,"servers":{"home":{"agent_id":"a","site_id":"s","agent_token":"t"},
"work":{"agent_id":"b","site_id":"s","agent_token":"u"}}}
EOF
run_install --server-url http://s:1 --wait 0 && check "exit!=0" "exit=0" "no token, no 'default' entry" \
	|| printf '  ok   %-28s -> refused\n' "no token, no 'default' entry"

cat > "$INST/etc/nettact/data/agent.json" <<'EOF'
{
  "v": 2,
  "servers": {
    "default": {
      "agent_id": "agent_1",
      "site_id": "site_default",
      "agent_token": "tok"
    }
  }
}
EOF
run_install --server-url http://s:1 --wait 0 \
	&& printf '  ok   %-28s -> accepted\n' "no token, already enrolled" \
	|| { printf '  FAIL %-28s -> refused\n' "no token, already enrolled"; fail=1; }

# The ordinary install.
run_install --server-url http://srv:12450 --token tok-1 --mode flash \
	--permissions 'probe.icmp,probe.dns' --wait 0 || true
check "http://srv:12450" "$(ucival server_url)" "server_url"
check "tok-1" "$(ucival enroll_token)" "enroll_token"
check "single" "$(ucival server_mode)" "server_mode"
check "flash" "$(ucival mode)" "mode"
check "custom" "$(ucival permission_mode)" "permission_mode"
check "probe.icmp probe.dns" "$(ucival permissions)" "permissions"
check "1" "$(ucival enabled)" "enabled"
check "enable restart" "$(tr '\n' ' ' < "$INST/init.log" | sed 's/ *$//')" "service actions"
check "2" "$(grep -c '\.ipk' "$INST/opkg.log")" "packages installed"

# enabled=1 must be written AFTER the server: the package ships enabled='0' so
# that installing it cannot make a router report to a server nobody configured,
# and that property has to hold until there is one.
enabled_at="$(grep -n '^set nettact.main.enabled=1' "$INST/uci.log" | head -n 1 | cut -d: -f1)"
server_at="$(grep -n '^set nettact.main.server_url=' "$INST/uci.log" | head -n 1 | cut -d: -f1)"
if [ -n "$enabled_at" ] && [ -n "$server_at" ] && [ "$enabled_at" -gt "$server_at" ]; then
	printf '  ok   %-28s -> line %s after %s\n' "enabled written last" "$enabled_at" "$server_at"
else
	printf '  FAIL %-28s -> enabled@%s server@%s\n' "enabled written last" "${enabled_at:-none}" "${server_at:-none}"
	fail=1
fi

# The regression that matters: a second run REPLACES the grant. Unioning it with
# the previous one would widen a permission set nobody widened.
rerun_install --server-url http://srv:12450 --token tok-2 --permissions 'probe.http' --wait 0 || true
check "probe.http" "$(ucival permissions)" "permissions replaced"
check "custom" "$(ucival permission_mode)" "permission_mode kept"

# "none" is a grant, not an absence: it must not leave a stale custom list behind.
rerun_install --server-url http://srv:12450 --token tok-3 --permissions none --wait 0 || true
check "none" "$(ucival permission_mode)" "permission_mode none"
check "" "$(ucival permissions)" "permissions cleared"

# Omitting --permissions leaves whatever was configured alone rather than
# silently resetting a router to the default grant.
rerun_install --server-url http://srv:12450 --token tok-4 --wait 0 || true
check "none" "$(ucival permission_mode)" "permission_mode untouched"

# A value wrapped across a shell line keeps its ids intact: only whitespace goes,
# and every character of a permission id stays.
rerun_install --server-url http://srv:12450 --token tok-5 --permissions ' probe.icmp,
	probe.dns ' --wait 0 || true
check "probe.icmp probe.dns" "$(ucival permissions)" "whitespace trimmed"

run_install --server-url http://srv:12450 --token t --no-luci --wait 0 || true
check "1" "$(grep -c '\.ipk' "$INST/opkg.log")" "--no-luci installs one package"

run_install --server-url http://srv:12450 --token t --ipk-base /tmp/out --wait 0 || true
check "1" "$(grep -c 'install /tmp/out/nettact-agent.ipk' "$INST/opkg.log")" "local --ipk-base"

# The online check. A live pid plus a connected server is success; the same file
# naming a dead process is the respawn loop this exists to catch, so it must time
# out instead of believing it.
printf '{"schema":1,"pid":%d,"agent_version":"v1","servers":[{"name":"default","state":"connected"}]}\n' "$$" > "$INST/tmp/status.json"
run_install --server-url http://srv:12450 --token t --wait 9 \
	&& printf '  ok   %-28s -> connected\n' "status: live pid" \
	|| { printf '  FAIL %-28s -> not detected\n' "status: live pid"; fail=1; }

dead=4194303
while kill -0 "$dead" 2>/dev/null; do dead=$(( dead - 1 )); done
printf '{"schema":1,"pid":%d,"agent_version":"v1","servers":[{"name":"default","state":"connected"}]}\n' "$dead" > "$INST/tmp/status.json"
run_install --server-url http://srv:12450 --token t --wait 6 \
	&& { printf '  FAIL %-28s -> reported connected\n' "status: dead pid"; fail=1; } \
	|| printf '  ok   %-28s -> not connected\n' "status: dead pid"

# A server that is reachable but not connected is not success either.
printf '{"schema":1,"pid":%d,"agent_version":"v1","servers":[{"name":"default","state":"connecting"}]}\n' "$$" > "$INST/tmp/status.json"
run_install --server-url http://srv:12450 --token t --wait 6 \
	&& { printf '  FAIL %-28s -> reported connected\n' "status: connecting" ; fail=1; } \
	|| printf '  ok   %-28s -> not connected\n' "status: connecting"

rm -f "$INST/tmp/status.json"

# --reinstall: the console mints a token bound to one agent, and the agent
# prefers a saved credential over any token — so the credential has to go, but
# only reversibly. Losing a working credential AND its queue because a URL was
# wrong is not a trade this should ever make.
cat > "$INST/etc/nettact/data/agent.json" <<'EOF'
{"v":2,"servers":{"default":{"agent_id":"a","site_id":"s","agent_token":"old"}}}
EOF
mkdir -p "$INST/etc/nettact/data/wal" && : > "$INST/etc/nettact/data/wal/seg-1"

run_install --server-url http://srv:12450 --reinstall --wait 0 \
	&& { printf '  FAIL %-28s -> accepted\n' "--reinstall without a token"; fail=1; } \
	|| printf '  ok   %-28s -> refused\n' "--reinstall without a token"
if [ -s "$INST/etc/nettact/data/agent.json" ]; then
	printf '  ok   %-28s -> untouched\n' "refusal keeps the credential"
else
	printf '  FAIL %-28s -> deleted\n' "refusal keeps the credential"; fail=1
fi

# The safety property is WHEN the wipe happens, not a backup: anything that can
# still abort — a bad option, a failed uci write — aborts with the working
# credential untouched, because the wipe is the last thing before the restart.
rerun_install --server-url http://srv:12450 --token new-tok --reinstall --mode bogus --wait 0 \
	&& { printf '  FAIL %-28s -> accepted\n' "--reinstall, bad option"; fail=1; } \
	|| printf '  ok   %-28s -> refused\n' "--reinstall, bad option"
check "old" "$(sed -n 's/.*"agent_token":"\([^"]*\)".*/\1/p' "$INST/etc/nettact/data/agent.json" 2>/dev/null)" "abort keeps credential"
[ -e "$INST/etc/nettact/data/wal/seg-1" ] \
	&& printf '  ok   %-28s -> kept\n' "abort keeps queue" \
	|| { printf '  FAIL %-28s -> lost\n' "abort keeps queue"; fail=1; }

# Once the service starts the contract is the native installer's: the previous
# identity is replaced, so the token given here is the one that enrolls.
printf '{"schema":1,"pid":%d,"servers":[{"name":"default","state":"connected"}]}\n' "$$" > "$INST/tmp/status.json"
rerun_install --server-url http://srv:12450 --token new-tok --reinstall --wait 9 \
	&& printf '  ok   %-28s -> connected\n' "--reinstall that connects" \
	|| { printf '  FAIL %-28s -> failed\n' "--reinstall that connects"; fail=1; }
[ -e "$INST/etc/nettact/data/agent.json" ] \
	&& { printf '  FAIL %-28s -> kept\n' "reinstall replaces identity"; fail=1; } \
	|| printf '  ok   %-28s -> replaced\n' "reinstall replaces identity"
rm -f "$INST/tmp/status.json"

# `--permissions default` is an explicit reset, not a no-op: the console shows
# "recommended", so a rerun must land on the built-in grant rather than keep a
# broader one the router happened to be carrying.
rerun_install --server-url http://srv:12450 --token t --permissions full --wait 0 || true
rerun_install --server-url http://srv:12450 --token t --permissions default --wait 0 || true
check "default" "$(ucival permission_mode)" "--permissions default resets"
check "" "$(ucival permissions)" "--permissions default clears"

[ "$fail" = 0 ] && echo "all checks passed" || echo "FAILURES" >&2
exit "$fail"
