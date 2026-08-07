#!/bin/sh
# Offline checks for the OpenWrt shell components.
#
# The real thing needs a router; this covers the part most likely to be wrong
# without one — the architecture table, which decides WHICH binary a device
# downloads and whose failure mode (a mipsel box fetching a hardfloat build) is
# a boot loop rather than an error message.
#
# opkg and uci are stubbed, so this runs anywhere with a POSIX shell.
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

for key in running enabled enrolled binary_present mode config_source config_path log; do
	case " $out " in
		*" $key"*) printf '  ok   %-28s -> present\n' "status.$key" ;;
		*) printf '  FAIL %-28s -> missing\n' "status.$key"; fail=1 ;;
	esac
done

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

[ "$fail" = 0 ] && echo "all checks passed" || echo "FAILURES" >&2
exit "$fail"
