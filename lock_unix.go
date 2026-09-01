//go:build !windows

package connectorhost

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

type processLock interface{ Close() error }
type unixProcessLock struct{ file *os.File }

func acquireProcessLock(path string) (processLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.Join(ErrStateLocked, err)
		}
		return nil, err
	}
	return &unixProcessLock{file: file}, nil
}
func (l *unixProcessLock) Close() error {
	return errors.Join(unix.Flock(int(l.file.Fd()), unix.LOCK_UN), l.file.Close())
}
