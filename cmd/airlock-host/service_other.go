//go:build !linux && !windows

package main

import "errors"

func newNativeServiceManager() (nativeServiceManager, error) {
	return nil, errors.New("airlock-host: managed services are supported on Linux and Windows")
}

func runNativeService([]string) (bool, error) {
	return false, nil
}
