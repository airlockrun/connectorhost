//go:build !windows

package connectorhost

import (
	"os"
	"os/exec"
	"syscall"
)

func configureContainedCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func containedCommandStarted(command *exec.Cmd) (func() error, func(), error) {
	terminate := func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return nil
		}
		return err
	}
	return terminate, func() { _ = terminate() }, nil
}
