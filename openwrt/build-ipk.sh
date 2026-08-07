#!/bin/sh
# Build the two OpenWrt packages.
#
#   ./build-ipk.sh <version> <output-dir>
#
# Neither package contains a compiled binary — nettact-agent downloads the agent
# at runtime and luci-app-nettact is JavaScript — so there is nothing to
# cross-compile and no OpenWrt SDK is needed. tar, gzip and a POSIX shell are
# enough, which is why this runs unchanged on a CI runner or a developer laptop.
#
# An ipk is an ar or tar archive of three members:
#   debian-binary    the text "2.0"
#   control.tar.gz   package metadata and maintainer scripts
#   data.tar.gz      the files themselves, rooted at /
# The outer container is a gzipped tar here, which opkg has read for many years
# and which needs no `ar` on the build host.
set -eu

VERSION="${1:-}"
OUTDIR="${2:-}"
[ -n "$VERSION" ] && [ -n "$OUTDIR" ] || {
	echo "usage: build-ipk.sh <version> <output-dir>" >&2
	exit 2
}

HERE="$(cd "$(dirname "$0")" && pwd)"
# Package versions may not carry the leading v of a release tag.
PKGVER="${VERSION#v}"

mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# tar_reproducible keeps ownership and timestamps out of the archive so the same
# inputs always yield the same bytes — a rebuilt package that differs only in
# metadata is noise in a release diff.
tar_reproducible() {
	tar --numeric-owner --owner=0 --group=0 --mtime='@0' \
		--format=gnu -czf "$@"
}

# compile_lmo turns the .po catalogs into the binary form LuCI loads. The C
# po2lmo from the OpenWrt build tree is used when it is on PATH, since it is the
# definition of the format; the bundled Python one covers every other machine.
compile_lmo() {
	src="$1" dst="$2"
	if command -v po2lmo >/dev/null 2>&1; then
		po2lmo "$src" "$dst"
		return
	fi
	for py in "${PYTHON:-}" python3 python; do
		[ -n "$py" ] || continue
		# Being on PATH is not enough to be usable: Windows ships a Microsoft
		# Store stub named python3 that resolves fine and then exits 49 without
		# running anything. Ask each candidate to prove it works first.
		"$py" -c "" >/dev/null 2>&1 || continue
		"$py" "$HERE/tools/po2lmo.py" "$src" "$dst"
		return
	done
	echo "build-ipk.sh: need po2lmo or python to compile translations" >&2
	exit 1
}

# lmo_lang maps a po/ directory name onto the language tag LuCI actually looks
# for at runtime. The two differ: LuCI keeps sources under zh_Hans but installs
# the catalog as zh-cn, so a mechanical lowercase-and-dash would produce a file
# nothing ever loads. Anything not in the table is close enough to pass through.
lmo_lang() {
	case "$1" in
		zh_Hans) echo zh-cn ;;
		zh_Hant) echo zh-tw ;;
		*) echo "$1" | tr 'A-Z_' 'a-z-' ;;
	esac
}

build_one() {
	pkgdir="$1" name="$2"
	stage="$WORK/$name"
	rm -rf "$stage"
	mkdir -p "$stage/data" "$stage/control"

	cp -R "$pkgdir/files/." "$stage/data/"

	# Executable bits do not survive a checkout on every filesystem (Windows has
	# no concept of one), so they are set here rather than trusted.
	for f in \
		"$stage/data/etc/init.d/nettact" \
		"$stage/data/usr/lib/nettact/fetch.sh" \
		"$stage/data/usr/lib/nettact/genconfig.sh" \
		"$stage/data/usr/lib/nettact/launch.sh" \
		"$stage/data/usr/libexec/rpcd/luci.nettact"
	do
		[ -f "$f" ] && chmod 0755 "$f"
	done
	# common.sh is sourced, never executed.
	[ -f "$stage/data/usr/lib/nettact/common.sh" ] && chmod 0644 "$stage/data/usr/lib/nettact/common.sh"

	if [ -d "$pkgdir/po" ]; then
		mkdir -p "$stage/data/usr/lib/lua/luci/i18n"
		for po in "$pkgdir"/po/*/*.po; do
			[ -f "$po" ] || continue
			lang="$(basename "$(dirname "$po")")"
			base="$(basename "$po" .po)"
			compile_lmo "$po" "$stage/data/usr/lib/lua/luci/i18n/$base.$(lmo_lang "$lang").lmo"
		done
	fi

	sed "s/@VERSION@/$PKGVER/g" "$pkgdir/control/control" > "$stage/control/control"
	# Installed-Size lets opkg refuse an install that would not fit, which is the
	# whole point on a router with 4 MB of free overlay.
	size="$(find "$stage/data" -type f -exec cat {} + 2>/dev/null | wc -c | tr -d ' ')"
	echo "Installed-Size: $size" >> "$stage/control/control"

	for extra in conffiles preinst postinst prerm postrm; do
		if [ -f "$pkgdir/control/$extra" ]; then
			cp "$pkgdir/control/$extra" "$stage/control/$extra"
			case "$extra" in
				conffiles) chmod 0644 "$stage/control/$extra" ;;
				*) chmod 0755 "$stage/control/$extra" ;;
			esac
		fi
	done

	( cd "$stage/control" && tar_reproducible "$stage/control.tar.gz" . )
	( cd "$stage/data" && tar_reproducible "$stage/data.tar.gz" . )
	echo "2.0" > "$stage/debian-binary"

	( cd "$stage" && tar_reproducible "$OUTDIR/$name.ipk" \
		./debian-binary ./control.tar.gz ./data.tar.gz )
	echo "built $OUTDIR/$name.ipk ($size bytes of payload)"
}

build_one "$HERE/nettact-agent" nettact-agent
build_one "$HERE/luci-app-nettact" luci-app-nettact
