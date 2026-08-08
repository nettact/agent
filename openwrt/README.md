# OpenWrt packages

Two ipks, neither containing a compiled binary:

- **`nettact-agent`** — procd service, UCI config, and the script that downloads
  the agent. Architecture `all`.
- **`luci-app-nettact`** — the LuCI pages, their rpcd backend, and the Chinese
  translation. Architecture `all`, depends on `nettact-agent`.

`install.sh` here installs both, writes the connection settings into
`/etc/config/nettact` and waits until the router reports itself connected — it
is what the console's OpenWrt tab hands out, served from the branch as
`https://d.nettact.org/agent/openwrt.sh`. It is a separate script from the
module's `install.sh` on purpose: that one is bash targeting systemd/launchd and
wipes the previous identity, both of which are wrong for a router (see the
header comment).

## Why nothing is bundled

A full agent is around 11 MB. Shipping it would mean a package per CPU
architecture and would not fit at all on the 8 and 16 MB routers this is most
useful on. Instead `fetch.sh` downloads the matching build at first start, and
the user chooses where it lands:

- `mode ram` — into `/tmp` on every boot. No flash used at all; costs ~11 MB of
  RAM and a download per reboot.
- `mode flash` — once into `/usr/lib/nettact`, so the router boots offline.

Either way the agent's identity (`agent.key`, `agent.json`) stays in
`/etc/nettact/data` on flash, so a reboot never means enrolling again. And
switching back to `ram` deletes the flash copy at the next start or download —
freeing the overlay is the whole reason for the switch, so leaving ~11 MB behind
would defeat it.

## How the agent is configured

The init script renders `/etc/config/nettact` into a YAML configuration at
`/var/etc/nettact/agent.yaml` and points the agent at it with
`NETTACT_AGENT_CONFIG_FILE`. Everything else the agent takes is in that file;
only `NETTACT_AGENT_DATA_DIR` still travels as an environment variable.

A file rather than environment variables because `servers:` — reporting to more
than one server — is a list of records, and the agent's environment model is one
key, one variable, one string. Rendering the whole document rather than that one
key keeps a single answer to "where did this setting come from". It lands on
tmpfs, so the enrollment token never comes to rest on flash a second time and
editing settings spends no overlay erase cycles.

`/etc/nettact/agent.yaml` is the escape hatch: when that file exists the init
script uses it verbatim and generates nothing, so the two can never disagree
about which config is live. The status page says which one is in effect.

The LuCI permission chooser carries its own copy of the permission catalog — a
router has no server to fetch one from — in
`luci-app-nettact/files/www/luci-static/resources/nettact/permcatalog.js`.
`permcatalog_test.go` holds it to `protocol/permission`, so editing one without
the other fails `go test ./...` in the agent module.

## What touches the flash

While a server's session is up, nothing does. The lite agent buffers telemetry
in RAM and uploads it seconds later; writing it to the overlay first would spend
erase cycles on data whose whole purpose is to be deleted again.

When a session drops, that stops being true. The samples piling up have nowhere
to go, and the next thing that usually happens is somebody power-cycling the
router to fix the internet — taking the record of how the fault started with it.
So from the moment a session ends the agent spills that server's unsent backlog
to `/etc/nettact/data/wal`, in the same segment format the full agent uses, and
uploads it after the reboot. `persist_enable` (default on) turns this off
entirely; `persist_window` (default `30m`) bounds how long after a disconnect it
keeps writing, so a week-long outage does not write for a week. Each server has
its own window — one being unreachable never makes another's telemetry touch the
flash — and once a backlog is acknowledged its segments are deleted, so a router
that has caught up occupies nothing again.

`install.sh --reinstall` removes that directory along with the credential, which
is the same thing it always did: the path did not change.

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

Stubs `opkg` and `uci` and checks the architecture table, version resolution,
the storage-mode paths, the stale-binary prune, the rendered YAML and the rpcd
contract. Three of those are worth testing offline in particular: picking the
wrong ARM variant is not a slow binary but a SIGILL on the first unsupported
instruction; a prune that took the flash directory rather than two files in it
would delete the package's own scripts; and a rendered config that carries both
`server_url:` and `servers:` is rejected by the agent, which takes the router
off the air.

There is one gap the stubs cannot cover: whether the agent actually *accepts*
the document. To check that, render one and feed it to a real binary —

```sh
./test-scripts.sh                      # renders many shapes, checks the text
# then, against a build of the agent:
NETTACT_AGENT_DATA_DIR=/tmp/d nettact-agent --config /tmp/rendered.yaml
```

It should reach "server 1/N: …" and fail on the network, not on the config.

Everything else — procd supervision, the LuCI pages, a real download — needs an
actual device or an OpenWrt image under QEMU.

## Layout

```
nettact-agent/
  control/{control,conffiles,postinst,prerm}
  files/etc/config/nettact              UCI defaults + schema
  files/etc/init.d/nettact              procd service
  files/lib/upgrade/keep.d/nettact      what sysupgrade must preserve
  files/usr/lib/nettact/common.sh       shared paths + UCI accessors + prune
  files/usr/lib/nettact/genconfig.sh    UCI -> /var/etc/nettact/agent.yaml
  files/usr/lib/nettact/launch.sh       waits for clock/network, fetches, execs
  files/usr/lib/nettact/fetch.sh        arch table, download, verify, install
luci-app-nettact/
  control/{control,postinst,postrm}
  files/usr/libexec/rpcd/luci.nettact   ubus object luci.nettact (the file
                                        name *is* the object name)
  files/usr/share/luci/menu.d/          menu entries
  files/usr/share/rpcd/acl.d/           ACL for the ubus methods
  files/www/luci-static/resources/nettact/permcatalog.js
                                        permission table, kept in step with Go
                                        by ../permcatalog_test.go
  files/www/luci-static/resources/view/nettact/{status,settings}.js
  po/zh_Hans/nettact.po                 compiled to nettact.zh-cn.lmo
openwrt.go, permcatalog_test.go         the parity test for permcatalog.js
install.sh                              one-command installer (both ipks + UCI
                                        + online check); served as
                                        d.nettact.org/agent/openwrt.sh
tools/po2lmo.py                         .po -> .lmo without the OpenWrt SDK
```

Note the language naming: LuCI keeps sources under `zh_Hans` but loads the
compiled catalog as `zh-cn`, so `build-ipk.sh` maps between them rather than
transforming the string mechanically.
