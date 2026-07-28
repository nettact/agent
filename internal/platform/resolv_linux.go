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
func parseResolvConf(r io.Reader) []string {
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
		// A link-local v6 server may carry a %zone suffix; keep the address only.
		value, _, _ := strings.Cut(fields[1], "%")
		addr, err := netip.ParseAddr(value)
		if err != nil {
			continue
		}
		out = appendUnique(out, addr.Unmap().String())
	}
	return out
}

// systemNameservers reads the host's resolver list. A missing or unreadable
// resolv.conf yields no servers rather than an error: DNS configuration is one
// reported field, not a precondition for enumerating interfaces.
func systemNameservers() []string {
	f, err := os.Open(hostfs.EtcPath("resolv.conf"))
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseResolvConf(f)
}
