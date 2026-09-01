//go:build !windows

package connectorhost

import "syscall"

func processRunning(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}
