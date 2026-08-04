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
# Answers from the environment so each case can set its own config.
case "$*" in
	*nettact.main.mode*) printf '%s' "${T_MODE:-ram}" ;;
	*nettact.main.download_base*) printf '%s' "${T_BASE:-}" ;;
	*nettact.main.version*) printf '%s' "${T_VERSION:-}" ;;
	*) : ;;
esac
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

# --- rpcd status backend ---------------------------------------------------
#
# The log array is built by a shell loop, and getting that wrong is invisible:
# in ash every stage of a pipeline is its own subshell, so a `logread | while
# read` loop would accumulate the array in a child and the parent would emit an
# empty one. The LuCI panel just stays blank, with no error anywhere.

echo "rpcd status:"

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
    "$HERE/luci-app-nettact/files/usr/libexec/rpcd/nettact" > "$RPCD"
chmod 0755 "$RPCD"

out="$(T_ARCH=x86_64 "$RPCD" call status </dev/null 2>/dev/null || echo 'ERROR')"
got="$(printf '%s' "$out" | sed -n 's/.*log_entries:\([0-9]*\).*/\1/p')"
check "3" "${got:-0}" "status returns the log lines"

for key in running enabled enrolled binary_present mode log; do
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
