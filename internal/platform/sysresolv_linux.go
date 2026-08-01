//go:build linux

package platform

// SystemResolvers returns the resolver addresses the host uses when a probe does
// not pin one of its own, most-preferred first. On Linux that is the single
// system-wide /etc/resolv.conf list, in file order.
//
// It exists so a DNS monitor on the system resolver can still NAME the server it
// queried: the stdlib resolver never reports which address answered, so without
// this a resolution failure has no diagnosable subject. An unreadable
// configuration yields no servers rather than an error — an unnameable resolver
// is reported as unknown, never guessed.
//
// Link-local %zone suffixes are KEPT here (unlike the interface-inventory view):
// a diagnostic aimed at a bare fe80:: address cannot reach the resolver.
func SystemResolvers() []string { return readResolvConf(true) }
