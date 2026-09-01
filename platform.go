//go:build !arm

package connectorhost

import "runtime"

func platformArchitecture() string { return runtime.GOARCH }
