//go:build !linux && !windows

package main

import "errors"

const nativeServiceSupported = false

func newNativeServiceManager(scope nativeServiceScope) (nativeServiceManager, error) {
	if scope == nativeServiceUser {
		return nil, errors.New("airlock-host: per-user managed services are supported on Linux")
	}
	if scope != nativeServiceSystem {
		return nil, errors.New("airlock-host: invalid managed service scope")
	}
	return nil, errors.New("airlock-host: managed services are supported on Linux and Windows")
}

func runNativeService([]string) (bool, error) {
	return false, nil
}
