//go:build !windows

package collector

// Non-Windows builds retain the runtime sensor probe. Platforms whose gopsutil
// backend is not implemented naturally report unsupported when it returns no
// usable readings.
func nativeTemperaturePlatformSupported() bool { return true }
