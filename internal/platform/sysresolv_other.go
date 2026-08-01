//go:build !linux && !windows

package platform

// SystemResolvers returns nothing on platforms whose resolver configuration this
// package does not read yet (macOS reads it through SystemConfiguration, which
// lands with the rest of the macOS HAL). A DNS monitor on the system resolver
// therefore reports its resolver as unnameable rather than guessed, and the
// server reports the path diagnostic as unavailable instead of tracing a wrong
// endpoint.
func SystemResolvers() []string { return nil }
