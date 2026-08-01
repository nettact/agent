//go:build windows

package collector

// Windows' built-in MSAcpi_ThermalZoneTemperature provider does not expose a
// trustworthy hardware temperature on many machines. Do not probe it or
// advertise host.temperature.read until the Agent has a real hardware-sensor
// backend.
func nativeTemperaturePlatformSupported() bool { return false }
