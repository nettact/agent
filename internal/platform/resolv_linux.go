//go:build linux

package platform

import (
	"bufio"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/nettact/agent/internal/hostfs"
)

// Linux resolves names through a single system-wide resolver list
// (/etc/resolv.conf), not a per-adapter one the way Windows does. The interface
// collector's DNS field is therefore filled from that one list and attached to
// the interfaces that carry a default route — the ones actually reaching those
// servers. Reporting the same list on every interface (including loopback and
// down ones) would invent per-interface configuration that does not exist.

// parseResolvConf extracts the nameserver addresses from a resolv.conf stream,
// in file order and without duplicates. Comments (# or ;) and any other
// directive are ignored, as are entries that are not valid IP addresses.
//
// keepZone decides what happens to a link-local v6 server's %zone suffix
// (`nameserver fe80::1%eth0`). Interface INVENTORY drops it: the zone names the
// interface the row is already attached to, so repeating it there is noise.
// A DIAGNOSTIC endpoint keeps it, because without the zone the address is not
// routable — a trace aimed at a bare fe80:: address cannot reach the resolver
// the probe used.
func parseResolvConf(r io.Reader, keepZone bool) []string {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		value, zone, hasZone := strings.Cut(fields[1], "%")
		addr, err := netip.ParseAddr(value)
		if err != nil {
			continue
		}
		name := addr.Unmap().String()
		if keepZone && hasZone && zone != "" {
			name += "%" + zone
		}
		out = appendUnique(out, name)
	}
	return out
}

// systemNameservers reads the HOST's resolver list for interface inventory,
// through hostfs so a containerized agent reports the machine an operator wants
// monitored rather than its own namespace. A missing or unreadable resolv.conf
// yields no servers rather than an error: DNS configuration is one reported
// field, not a precondition for enumerating interfaces.
func systemNameservers() []string {
	return readResolvConf(hostfs.EtcPath("resolv.conf"), false)
}

// processNameservers reads THIS PROCESS's resolver list — deliberately the real
// /etc/resolv.conf rather than the hostfs redirection, because it answers a
// different question than the inventory above: which server did net.DefaultResolver
// just query? The stdlib reads the process's own file, so under HOST_ETC the two
// lists can differ, and reporting the host's would name a server this probe never
// sent a packet to.
func processNameservers(keepZone bool) []string {
	return readResolvConf("/etc/resolv.conf", keepZone)
}

// readResolvConf is the shared reader behind both the inventory and diagnostic
// views of the resolver list.
func readResolvConf(path string, keepZone bool) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseResolvConf(f, keepZone)
}
