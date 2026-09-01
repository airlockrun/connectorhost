//go:build !windows && !linux

package connectorhost

import (
	"os"
	"os/exec"
	"syscall"
)

func configureShellCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
}

func shellCommandStarted(*exec.Cmd) (func(), error) { return func() {}, nil }

func terminateInterruptedShell(processID int) error {
	if processID <= 0 {
		return nil
	}
	err := syscall.Kill(-processID, syscall.SIGKILL)
	if err == syscall.ESRCH {
		return nil
	}
	return err
}

func terminateShellHelper(*exec.Cmd) error {
	return syscall.Kill(-syscall.Getpgrp(), syscall.SIGKILL)
}
