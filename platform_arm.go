//go:build arm

package connectorhost

// Airlock publishes and addresses the supported 32-bit ARM target as armv7.
func platformArchitecture() string { return "armv7" }
