//go:build windows

package connectorhost

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func processRunning(pid int) bool {
	process, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(process)
	status, err := windows.WaitForSingleObject(process, 0)
	return err == nil && status == uint32(windows.WAIT_TIMEOUT)
}

func TestWindowsContainedProcessIsSuspendedUntilJobAssignment(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	command := exec.Command(os.Args[0], "-test.run=^TestWindowsContainedProcessHelper$")
	command.Env = append(os.Environ(), "AIRLOCK_CONNECTOR_HOST_TEST_WINDOWS_CONTAINED_HELPER="+marker)
	configureContainedCommand(command)
	if command.SysProcAttr.CreationFlags&windows.CREATE_SUSPENDED == 0 || command.SysProcAttr.CreationFlags&syscall.CREATE_NEW_PROCESS_GROUP == 0 {
		t.Fatalf("contained creation flags = %#x", command.SysProcAttr.CreationFlags)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("contained process executed before job assignment: %v", err)
	}
	terminate, cleanup, err := containedCommandStarted(command)
	if err != nil {
		_ = command.Wait()
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = terminate()
			_ = command.Wait()
			cleanup()
			t.Fatal("contained process did not resume")
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = terminate()
	_ = command.Wait()
	cleanup()
}

func TestWindowsContainedProcessHelper(t *testing.T) {
	marker := os.Getenv("AIRLOCK_CONNECTOR_HOST_TEST_WINDOWS_CONTAINED_HELPER")
	if marker == "" {
		return
	}
	if err := os.WriteFile(marker, []byte("executed"), 0o600); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Hour)
	}
}
