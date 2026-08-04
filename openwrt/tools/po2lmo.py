#!/usr/bin/env python3
"""Compile a gettext .po file into LuCI's .lmo catalog format.

LuCI ships a C tool for this (modules/luci-base/src/po2lmo.c, Apache-2.0), but
it only exists inside an OpenWrt build tree. Reimplementing it here means the
ipks can be built on any machine with Python — no SDK, no cross toolchain, no
vendored C.

build-ipk.sh prefers a real `po2lmo` binary when PATH has one; this is the
fallback. If they ever disagree the C tool is right by definition.

Format (from lmo.h and po2lmo.c):

  [string area][index][uint32 index_offset]

  * String area: each translated string written as raw bytes with NO
    terminating NUL, padded with NULs to a 4-byte boundary.
  * Index: one 16-byte record per entry, all big-endian:
        key_id  SuperFastHash of the msgid, seeded with its byte length
        val_id  plural form count (1 for an ordinary singular message)
        offset  byte offset of the string within the string area
        length  byte length of the string, unpadded
    Records are sorted ascending by unsigned key_id so lookup can binary-search.
  * Trailing uint32: the size of the string area, i.e. where the index starts.

  The PO header's Plural-Forms line, if present, is stored as an entry with
  key_id = 0 and val_id = 0.
"""

import struct
import sys


def sfh_hash(data: bytes, init: int) -> int:
    """SuperFastHash (Paul Hsieh), the variant LuCI seeds with the length.

    Kept byte-exact: a hash that differs from LuCI's by even one bit produces a
    catalog that loads fine and never matches a single string.
    """
    mask = 0xFFFFFFFF
    length = len(data)
    if length <= 0:
        return 0

    def get16(off: int) -> int:
        return data[off] | (data[off + 1] << 8)

    hash_ = init & mask
    rem = length & 3
    words = length >> 2
    pos = 0

    for _ in range(words):
        hash_ = (hash_ + get16(pos)) & mask
        tmp = ((get16(pos + 2) << 11) ^ hash_) & mask
        hash_ = ((hash_ << 16) ^ tmp) & mask
        pos += 4
        hash_ = (hash_ + (hash_ >> 11)) & mask

    # The C original indexes a `char`, which is signed on the platforms LuCI
    # builds for, so bytes >= 0x80 sign-extend. msgids are ASCII in practice,
    # but reproducing it keeps the hash correct if one ever is not.
    def signed(b: int) -> int:
        return b - 256 if b > 127 else b

    if rem == 3:
        hash_ = (hash_ + get16(pos)) & mask
        hash_ = (hash_ ^ (hash_ << 16)) & mask
        hash_ = (hash_ ^ ((signed(data[pos + 2]) << 18) & mask)) & mask
        hash_ = (hash_ + (hash_ >> 11)) & mask
    elif rem == 2:
        hash_ = (hash_ + get16(pos)) & mask
        hash_ = (hash_ ^ (hash_ << 11)) & mask
        hash_ = (hash_ + (hash_ >> 17)) & mask
    elif rem == 1:
        hash_ = (hash_ + signed(data[pos])) & mask
        hash_ = (hash_ ^ (hash_ << 10)) & mask
        hash_ = (hash_ + (hash_ >> 1)) & mask

    hash_ = (hash_ ^ (hash_ << 3)) & mask
    hash_ = (hash_ + (hash_ >> 5)) & mask
    hash_ = (hash_ ^ (hash_ << 4)) & mask
    hash_ = (hash_ + (hash_ >> 17)) & mask
    hash_ = (hash_ ^ (hash_ << 25)) & mask
    hash_ = (hash_ + (hash_ >> 6)) & mask
    return hash_


def unquote(line: str):
    """Return the contents of the first double-quoted run on a PO line."""
    start = line.find('"')
    if start < 0:
        return None
    out = []
    i = start + 1
    while i < len(line):
        c = line[i]
        if c == "\\":
            i += 1
            if i >= len(line):
                break
            nxt = line[i]
            out.append({"n": "\n", "t": "\t", "r": "\r"}.get(nxt, nxt))
        elif c == '"':
            break
        else:
            out.append(c)
        i += 1
    return "".join(out)


def parse_po(text: str):
    """Yield (msgid, msgstr) pairs, plus the header block as msgid ''."""
    msgid = msgstr = None
    field = None
    entries = []

    def flush():
        if msgid is not None:
            entries.append((msgid, msgstr or ""))

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("msgid_plural"):
            # Plural messages need the C tool's key encoding; the LuCI views in
            # this package use none, so refusing beats emitting a wrong catalog.
            raise SystemExit("po2lmo.py: plural forms are not supported; use the C po2lmo")
        if line.startswith("msgctxt"):
            raise SystemExit("po2lmo.py: message contexts are not supported; use the C po2lmo")
        if line.startswith("msgid"):
            flush()
            msgid, msgstr, field = unquote(line), None, "id"
        elif line.startswith("msgstr"):
            msgstr, field = unquote(line), "str"
        elif line.startswith('"'):
            piece = unquote(line)
            if field == "id":
                msgid = (msgid or "") + piece
            elif field == "str":
                msgstr = (msgstr or "") + piece
    flush()
    return entries


def compile_po(text: str) -> bytes:
    records = []  # (key_id, val_id, value_bytes)
    for msgid, msgstr in parse_po(text):
        if msgid == "":
            for header_line in msgstr.split("\n"):
                if header_line.startswith("Plural-Forms:"):
                    plural = header_line[len("Plural-Forms:"):].strip()
                    records.append((0, 0, plural.encode("utf-8")))
            continue
        if not msgstr:
            continue  # untranslated: let the source string show through
        key = msgid.encode("utf-8")
        records.append((sfh_hash(key, len(key)), 1, msgstr.encode("utf-8")))

    records.sort(key=lambda r: r[0])

    strings = bytearray()
    index = bytearray()
    for key_id, val_id, value in records:
        offset = len(strings)
        strings += value
        strings += b"\0" * ((4 - (len(value) % 4)) % 4)
        index += struct.pack(">IIII", key_id, val_id, offset, len(value))

    if not strings:
        return b""
    return bytes(strings) + bytes(index) + struct.pack(">I", len(strings))


def read_back(blob: bytes):
    """Independent reader, used to self-check what compile_po produced."""
    idx_offset = struct.unpack(">I", blob[-4:])[0]
    body = blob[idx_offset:-4]
    if len(body) % 16:
        raise SystemExit("po2lmo.py: index is not a whole number of records")
    out = []
    prev = -1
    for i in range(0, len(body), 16):
        key_id, val_id, offset, length = struct.unpack(">IIII", body[i:i + 16])
        if key_id < prev:
            raise SystemExit("po2lmo.py: index is not sorted by key_id")
        prev = key_id
        if offset + length > idx_offset:
            raise SystemExit("po2lmo.py: string range runs past the string area")
        out.append((key_id, val_id, blob[offset:offset + length].decode("utf-8")))
    return out


def main(argv):
    if len(argv) != 3:
        raise SystemExit("usage: po2lmo.py input.po output.lmo")
    with open(argv[1], "r", encoding="utf-8") as fh:
        text = fh.read()

    blob = compile_po(text)
    if not blob:
        raise SystemExit("po2lmo.py: %s produced no translations" % argv[1])

    # Structural self-check: a catalog that cannot be walked back is one that
    # would fail silently at runtime, showing English and explaining nothing.
    entries = read_back(blob)
    expected = sum(1 for k, v in parse_po(text) if (k == "" and "Plural-Forms:" in (v or "")) or (k and v))
    if len(entries) != expected:
        raise SystemExit("po2lmo.py: wrote %d entries, expected %d" % (len(entries), expected))

    with open(argv[2], "wb") as fh:
        fh.write(blob)
    print("po2lmo.py: %s -> %s (%d entries, %d bytes)" % (argv[1], argv[2], len(entries), len(blob)))


if __name__ == "__main__":
    main(sys.argv)
