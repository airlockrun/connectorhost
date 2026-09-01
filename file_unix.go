//go:build !windows

package connectorhost

import "os"

func replaceFile(from, to string) error { return os.Rename(from, to) }
func secureDirectory(path string) error { return os.Chmod(path, 0o700) }
func secureFile(path string) error      { return os.Chmod(path, 0o600) }
func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
