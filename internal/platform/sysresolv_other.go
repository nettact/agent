//go:build !linux && !windows && !darwin

package platform

// SystemResolvers returns nothing on platforms whose resolver configuration this
// package does not read. A DNS monitor on the system resolver therefore reports
// its resolver as unnameable rather than guessed, and the server reports the
// path diagnostic as unavailable instead of tracing a wrong endpoint.
func SystemResolvers() []string { return nil }
