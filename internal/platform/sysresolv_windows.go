//go:build windows

package platform

// SystemResolvers returns the resolver addresses the host uses when a probe does
// not pin one of its own, most-preferred first. Windows configures DNS per
// adapter, so the list is assembled from the adapter table rather than one file.
//
// It exists so a DNS monitor on the system resolver can still NAME the server it
// queried: the stdlib resolver never reports which address answered, so without
// this a resolution failure has no diagnosable subject. An enumeration error
// yields no servers rather than an error — an unnameable resolver is reported as
// unknown, never guessed.
func SystemResolvers() []string {
	ifaces, err := (winPlatform{}).Interfaces(IfaceQuery{DNS: true, Gateways: true})
	if err != nil {
		return nil
	}
	return pickSystemResolvers(ifaces)
}

// pickSystemResolvers orders the adapter table's DNS servers the way Windows
// itself would reach them: default-route adapters first, then the rest, dropping
// down and loopback adapters entirely. The resolver a query actually lands on
// depends on the interface metric this cannot see, so the order is a best effort
// and the FIRST entry is the one reported — a wrong guess would name a server the
// query never touched, which is why down adapters are excluded rather than ranked
// last.
func pickSystemResolvers(ifaces []IfaceInfo) []string {
	var withGateway, rest []string
	for _, f := range ifaces {
		if !f.Up || f.IsLoopback || len(f.DNS) == 0 {
			continue
		}
		if len(f.Gateways) > 0 {
			withGateway = append(withGateway, f.DNS...)
			continue
		}
		rest = append(rest, f.DNS...)
	}
	var out []string
	for _, v := range append(withGateway, rest...) {
		out = appendUnique(out, v)
	}
	return out
}
