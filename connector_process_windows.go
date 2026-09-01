//go:build windows

package connectorhost

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func configureContainedCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | windows.CREATE_SUSPENDED}
}

func containedCommandStarted(command *exec.Cmd) (func() error, func(), error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		_ = command.Process.Kill()
		return nil, nil, err
	}
	cleanup := func() { _ = windows.CloseHandle(job) }
	fail := func(err error, assigned bool) (func() error, func(), error) {
		if assigned {
			_ = windows.TerminateJobObject(job, 1)
		} else {
			_ = command.Process.Kill()
		}
		cleanup()
		return nil, nil, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return fail(err, false)
	}
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(command.Process.Pid))
	if err != nil {
		return fail(err, false)
	}
	defer windows.CloseHandle(process)
	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		return fail(err, false)
	}
	threadID, err := suspendedProcessThreadID(uint32(command.Process.Pid))
	if err != nil {
		return fail(err, true)
	}
	thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, threadID)
	if err != nil {
		return fail(err, true)
	}
	previousSuspendCount, resumeErr := windows.ResumeThread(thread)
	_ = windows.CloseHandle(thread)
	if resumeErr != nil {
		return fail(resumeErr, true)
	}
	if previousSuspendCount != 1 {
		return fail(errors.New("connectorhost: contained process primary thread had an unexpected suspend count"), true)
	}
	terminate := func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		return windows.TerminateJobObject(job, 1)
	}
	return terminate, cleanup, nil
}

func suspendedProcessThreadID(processID uint32) (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	if err := windows.Thread32First(snapshot, &entry); err != nil {
		return 0, err
	}
	var threadID uint32
	for {
		if entry.OwnerProcessID == processID {
			if threadID != 0 {
				return 0, errors.New("connectorhost: suspended process has multiple threads before containment")
			}
			threadID = entry.ThreadID
		}
		err = windows.Thread32Next(snapshot, &entry)
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			break
		}
		if err != nil {
			return 0, err
		}
	}
	if threadID == 0 {
		return 0, errors.New("connectorhost: suspended process primary thread was not found")
	}
	return threadID, nil
}
