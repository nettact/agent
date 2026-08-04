# OpenWrt packages

Two ipks, neither containing a compiled binary:

- **`nettact-agent`** — procd service, UCI config, and the script that downloads
  the agent. Architecture `all`.
- **`luci-app-nettact`** — the LuCI pages, their rpcd backend, and the Chinese
  translation. Architecture `all`, depends on `nettact-agent`.

## Why nothing is bundled

A full agent is around 11 MB. Shipping it would mean a package per CPU
architecture and would not fit at all on the 8 and 16 MB routers this is most
useful on. Instead `fetch.sh` downloads the matching build at first start, and
the user chooses where it lands:

- `mode ram` — into `/tmp` on every boot. No flash used at all; costs ~11 MB of
  RAM and a download per reboot.
- `mode flash` — once into `/usr/lib/nettact`, so the router boots offline.

Either way the agent's identity (`agent.key`, `agent.json`) stays in
`/etc/nettact/data` on flash, so a reboot never means enrolling again.

## Building

```sh
./build-ipk.sh v1.2.3 ./out
```

Needs only a POSIX shell, `tar` and `gzip`, plus `po2lmo` **or** Python for the
translations (`tools/po2lmo.py` is used when the C tool is not on PATH). No
OpenWrt SDK and no cross toolchain.

## Testing without a router

```sh
./test-scripts.sh
```

Stubs `opkg` and `uci` and checks the architecture table, version resolution and
the storage-mode paths. The architecture table is the part worth testing
offline: picking the wrong ARM variant is not a slow binary but a SIGILL on the
first unsupported instruction.

Everything else — procd supervision, the LuCI pages, a real download — needs an
actual device or an OpenWrt image under QEMU.

## Layout

```
nettact-agent/
  control/{control,conffiles,postinst,prerm}
  files/etc/config/nettact              UCI defaults
  files/etc/init.d/nettact              procd service
  files/lib/upgrade/keep.d/nettact      what sysupgrade must preserve
  files/usr/lib/nettact/common.sh       shared paths + UCI accessors
  files/usr/lib/nettact/launch.sh       waits for clock/network, fetches, execs
  files/usr/lib/nettact/fetch.sh        arch table, download, verify, install
luci-app-nettact/
  control/{control,postinst,postrm}
  files/usr/libexec/rpcd/nettact        ubus object luci.nettact
  files/usr/share/luci/menu.d/          menu entries
  files/usr/share/rpcd/acl.d/           ACL for the ubus methods
  files/www/luci-static/resources/view/nettact/{status,settings}.js
  po/zh_Hans/nettact.po                 compiled to nettact.zh-cn.lmo
tools/po2lmo.py                         .po -> .lmo without the OpenWrt SDK
```

Note the language naming: LuCI keeps sources under `zh_Hans` but loads the
compiled catalog as `zh-cn`, so `build-ipk.sh` maps between them rather than
transforming the string mechanically.
