//go:build windows

package connectorhost

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

type processLock interface{ Close() error }
type windowsProcessLock struct {
	file       *os.File
	overlapped windows.Overlapped
}

func acquireProcessLock(path string) (processLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	lock := &windowsProcessLock{file: file}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &lock.overlapped); err != nil {
		_ = file.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errors.Join(ErrStateLocked, err)
		}
		return nil, err
	}
	return lock, nil
}
func (l *windowsProcessLock) Close() error {
	return errors.Join(windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, 1, 0, &l.overlapped), l.file.Close())
}
