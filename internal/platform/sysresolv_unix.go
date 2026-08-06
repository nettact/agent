//go:build linux || darwin

package platform

// SystemResolvers returns the resolver addresses THIS PROCESS queries when a
// probe does not pin one of its own, in the order they are configured, read
// from /etc/resolv.conf.
//
// On Linux that IS the process's resolver configuration. On macOS it is an
// approximation with a known, accepted gap: configd maintains resolv.conf as a
// mirror of the PRIMARY resolver only, while the OS resolver Go defers to
// honors the full scoped configuration (`scutil --dns`) — so under a split-DNS
// VPN a lookup may be served by a per-domain resolver this list does not name.
// Closing that gap needs the SystemConfiguration framework, which the cgo-free
// agent deliberately does not bind (see AGENT-005); a primary-resolver name
// remains more diagnosable than "unknown" for the common single-resolver case.
//
// It exists so a DNS monitor on the system resolver can still NAME the server it
// queried: the stdlib resolver never reports which address answered, so without
// this a resolution failure has no diagnosable subject. An unreadable
// configuration yields no servers rather than an error — an unnameable resolver
// is reported as unknown, never guessed.
//
// Link-local %zone suffixes are KEPT here (unlike the interface-inventory view):
// a diagnostic aimed at a bare fe80:: address cannot reach the resolver.
func SystemResolvers() []string { return processNameservers(true) }
