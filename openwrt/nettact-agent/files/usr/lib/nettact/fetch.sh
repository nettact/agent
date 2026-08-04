#!/bin/sh
# Download, verify and install the NetTact agent binary.
#
# The package ships no binary: ~11 MB is more than most routers can spare on
# flash, and the architectures OpenWrt spans would need a dozen variants of the
# package. One arch-independent package plus this script is smaller and covers
# every device.
#
#   fetch.sh install [version]   download (if needed) and install the binary
#   fetch.sh arch                print the asset architecture for this device
#   fetch.sh versions            print the download source's version list (JSON)
#   fetch.sh resolve [version]   print the concrete release tag that would be used
#
# Exit status is 0 on success, non-zero on any failure; the reason goes to stderr
# and to syslog.
set -e

. /usr/lib/nettact/common.sh

ASSET_PREFIX=nettact-agent-lite-linux
SUMS_FILE=SHA256SUMS

usage() {
	cat >&2 <<EOF
usage: fetch.sh install [version] | arch | versions | resolve [version]
EOF
	exit 2
}

# --- architecture -----------------------------------------------------------

# resolve_arch maps this device's OpenWrt architecture onto the asset naming the
# release uses. opkg is asked first because it names the architecture the
# packages were actually built for; OPENWRT_ARCH is the fallback for images
# where opkg is absent or its list is empty.
#
# Every mips entry maps to softfloat on purpose. MT7621/MT7620/MT76x8 — very
# nearly the whole ramips installed base — have no FPU, and a softfloat binary
# also runs correctly on the rare chips that do, so one variant covers the field
# with no way to pick the one that crashes.
resolve_arch() {
	local a
	a="$(opkg print-architecture 2>/dev/null | awk '$2 != "all" && $2 != "noarch" {print $2}' | tail -n 1)"
	if [ -z "$a" ] && [ -r /etc/os-release ]; then
		a="$(. /etc/os-release 2>/dev/null && printf '%s' "$OPENWRT_ARCH")"
	fi
	[ -n "$a" ] || { nettact_err "cannot determine this device's architecture"; return 1; }

	case "$a" in
		x86_64*)                   printf 'amd64' ;;
		i386_*|i486_*|i686_*|x86*) printf '386' ;;
		aarch64_*)                 printf 'arm64' ;;

		# ARMv5TE: no Thumb-2, no ARMv6 media instructions. Getting one of
		# these wrong is not a slow binary, it is SIGILL on the first
		# unsupported opcode, so each is listed rather than caught by a
		# pattern. XScale in particular reads modern but is ARMv5TE.
		arm_arm926*|arm_fa526*|arm_xscale*|arm_arm920*) printf 'armv5' ;;

		# ARMv6/v6K.
		arm_arm1176*|arm_mpcore*) printf 'armv6' ;;

		# ARMv7-A, including the 32-bit ARMv8 cores, which run ARMv7 code.
		arm_cortex-a5*|arm_cortex-a7*|arm_cortex-a8*|arm_cortex-a9*|arm_cortex-a1*|arm_cortex-a3*|arm_cortex-a5[0-9]*|arm_cortex-a7[0-9]*)
		                 printf 'armv7' ;;
		# Anything else on ARM: assume ARMv7. Every OpenWrt ARM target added in
		# the last decade is at least that, and the pre-v7 cores that exist are
		# all named above.
		arm_*|arm)       printf 'armv7' ;;

		# One softfloat build per endianness. MT7621/MT7620/MT76x8 — very
		# nearly the whole ramips installed base — have no FPU, and softfloat
		# also runs on the few chips that do, so there is no variant here that
		# can be picked wrongly.
		mipsel_*|mipsel) printf 'mipsle-softfloat' ;;
		mips_*|mips)     printf 'mips-softfloat' ;;

		riscv64*)        printf 'riscv64' ;;
		*) nettact_err "no NetTact agent build for architecture '$a'"; return 1 ;;
	esac
}

# --- download ---------------------------------------------------------------

# download fetches url to a file. uclient-fetch is what OpenWrt ships; wget and
# curl are accepted so the script also runs on a plain Linux box during testing.
# HTTPS needs ca-bundle plus an SSL backend for uclient-fetch (libustream-*),
# both present on stock images.
download() {
	local url="$1" dest="$2"
	if command -v uclient-fetch >/dev/null 2>&1; then
		uclient-fetch -q -O "$dest" "$url"
	elif command -v curl >/dev/null 2>&1; then
		curl -fsSL -o "$dest" "$url"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$dest" "$url"
	else
		nettact_err "no downloader available (need uclient-fetch, curl or wget)"
		return 1
	fi
}

base_url() {
	nettact_cfg download_base 'https://d.nettact.org/agent'
}

# resolve_version turns 'latest' into a concrete release tag, so the binary and
# the checksum list are always taken from ONE immutable versioned path. Reading
# them from the moving 'latest' path could straddle a release being published
# and fail the checksum against a binary that is perfectly good.
resolve_version() {
	local want="$1" tmp tag
	[ -n "$want" ] || want="$(nettact_cfg version latest)"
	[ -n "$want" ] || want=latest
	if [ "$want" != latest ]; then
		printf '%s' "$want"
		return 0
	fi
	tmp="$(mktemp)" || return 1
	# shellcheck disable=SC2064
	trap "rm -f '$tmp'" EXIT
	if ! download "$(base_url)/versions.json" "$tmp"; then
		nettact_err "cannot reach $(base_url)/versions.json"
		return 1
	fi
	tag="$(sed -n 's/.*"latest"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$tmp" | head -n 1)"
	rm -f "$tmp"
	trap - EXIT
	[ -n "$tag" ] || { nettact_err "no published release found at $(base_url)"; return 1; }
	printf '%s' "$tag"
}

# --- install ----------------------------------------------------------------

# free_kb reports free space on the filesystem holding dir, in KiB.
free_kb() {
	df -k "$1" 2>/dev/null | awk 'NR==2 {print $4}'
}

do_install() {
	local version arch dir bin url tmp want sum
	arch="$(resolve_arch)" || return 1
	version="$(resolve_version "$1")" || return 1
	dir="$(nettact_bin_dir)"
	bin="$dir/nettact-agent"

	mkdir -p "$dir" || return 1

	# The temp file must sit on the SAME filesystem as its destination so the
	# final move is a rename rather than a copy: a half-copied binary that procd
	# then executes is exactly the failure this avoids.
	tmp="$dir/.nettact-agent.download"
	rm -f "$tmp"
	# shellcheck disable=SC2064
	trap "rm -f '$tmp' '$tmp.sums'" EXIT

	if [ "$(nettact_mode)" = flash ]; then
		local avail
		avail="$(free_kb "$dir")"
		if [ -n "$avail" ] && [ "$avail" -lt 16384 ]; then
			nettact_err "only ${avail} KiB free on $dir; the agent needs about 12 MiB (switch mode to 'ram')"
			return 1
		fi
	fi

	url="$(base_url)/$version/$ASSET_PREFIX-$arch"
	nettact_log "downloading agent $version for $arch"
	if ! download "$url" "$tmp"; then
		nettact_err "download failed: $url"
		return 1
	fi
	if ! download "$(base_url)/$version/$SUMS_FILE" "$tmp.sums"; then
		nettact_err "cannot fetch $SUMS_FILE for $version"
		return 1
	fi

	want="$(awk -v n="$ASSET_PREFIX-$arch" '$2 == n || $2 == "*"n {print $1}' "$tmp.sums" | head -n 1)"
	if [ -z "$want" ]; then
		nettact_err "$SUMS_FILE for $version lists no $ASSET_PREFIX-$arch"
		return 1
	fi
	sum="$(sha256sum "$tmp" | awk '{print $1}')"
	if [ "$sum" != "$want" ]; then
		nettact_err "checksum mismatch for $ASSET_PREFIX-$arch: got $sum, expected $want"
		return 1
	fi

	if [ -f "$bin" ] && cmp -s "$tmp" "$bin"; then
		nettact_log "agent $version already installed at $bin"
		rm -f "$tmp" "$tmp.sums"
		trap - EXIT
		return 0
	fi

	chmod 0755 "$tmp" || return 1
	# Replacing a RUNNING binary: on Linux the rename detaches the old inode,
	# which the running process keeps using until it is restarted. That is the
	# intended behaviour — the caller restarts the service.
	mv -f "$tmp" "$bin" || return 1
	rm -f "$tmp.sums"
	trap - EXIT
	nettact_log "installed agent $version ($arch) to $bin"
}

# --- entry point ------------------------------------------------------------

case "${1:-install}" in
	install) do_install "$2" ;;
	arch) resolve_arch && echo ;;
	resolve) resolve_version "$2" && echo ;;
	versions)
		tmp="$(mktemp)" || exit 1
		trap 'rm -f "$tmp"' EXIT
		download "$(base_url)/versions.json" "$tmp" || exit 1
		cat "$tmp"
		;;
	*) usage ;;
esac
