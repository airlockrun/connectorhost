package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	connectorhost "github.com/airlockrun/connectorhost"
	"golang.org/x/sys/unix"
)

const (
	linuxServiceUnitName = "airlock-host.service"
	linuxServiceUser     = "airlock-host"
	linuxServiceGroup    = "airlock-host"
	linuxControlPort     = 42927
)

type linuxServicePaths struct {
	executable     string
	stateDirectory string
	unitFile       string
}

type linuxCommandRunner func(context.Context, string, ...string) ([]byte, error)

type linuxServiceManager struct {
	paths          linuxServicePaths
	currentExe     func() (string, error)
	effectiveUID   func() int
	runCommand     linuxCommandRunner
	ready          func(context.Context, string) error
	passwdFile     string
	commandTimeout time.Duration
}

func newNativeServiceManager() (nativeServiceManager, error) {
	return &linuxServiceManager{
		paths: linuxServicePaths{
			executable:     "/usr/local/bin/airlock-host",
			stateDirectory: "/var/lib/airlock-host",
			unitFile:       "/etc/systemd/system/airlock-host.service",
		},
		currentExe:     os.Executable,
		effectiveUID:   os.Geteuid,
		runCommand:     runLinuxCommand,
		ready:          linuxHostReady,
		passwdFile:     "/etc/passwd",
		commandTimeout: 30 * time.Second,
	}, nil
}

func runLinuxCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func runNativeService([]string) (bool, error) {
	return false, nil
}

func (m *linuxServiceManager) Install(ctx context.Context) error {
	if m.effectiveUID() != 0 {
		return errors.New("airlock-host: service installation requires root")
	}
	sourcePath, err := m.currentExe()
	if err != nil {
		return fmt.Errorf("airlock-host: locate current executable: %w", err)
	}
	source, err := openRegularFile(sourcePath)
	if err != nil {
		return fmt.Errorf("airlock-host: current executable: %w", err)
	}
	defer source.Close()

	if err := m.createAccount(ctx); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.paths.executable), 0o755); err != nil {
		return fmt.Errorf("airlock-host: create executable directory: %w", err)
	}
	if err := copyExecutableIfNeeded(ctx, source, m.paths.executable); err != nil {
		return fmt.Errorf("airlock-host: install executable: %w", err)
	}
	if err := os.MkdirAll(m.paths.stateDirectory, 0o750); err != nil {
		return fmt.Errorf("airlock-host: create state directory: %w", err)
	}
	if err := os.Chmod(m.paths.stateDirectory, 0o750); err != nil {
		return fmt.Errorf("airlock-host: set state directory permissions: %w", err)
	}
	if err := m.checkedCommand(ctx, "chown", "--recursive", "--no-dereference", linuxServiceUser+":"+linuxServiceGroup, m.paths.stateDirectory); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.paths.unitFile), 0o755); err != nil {
		return fmt.Errorf("airlock-host: create systemd unit directory: %w", err)
	}
	if err := writeFileIfNeeded(ctx, m.paths.unitFile, []byte(m.systemdUnit()), 0o644); err != nil {
		return fmt.Errorf("airlock-host: install systemd unit: %w", err)
	}
	if err := m.checkedCommand(ctx, "systemctl", "enable", linuxServiceUnitName); err != nil {
		return err
	}
	return m.reloadSystemd(ctx)
}

func (m *linuxServiceManager) Start(ctx context.Context) error {
	status, err := m.Status(ctx)
	if err != nil {
		return err
	}
	switch status.State {
	case serviceNotInstalled:
		return errors.New("airlock-host: service is not installed")
	case serviceRunning:
		return m.waitForReady(ctx)
	case serviceStartPending:
		if err := m.waitForState(ctx, serviceRunning); err != nil {
			return err
		}
		return m.waitForReady(ctx)
	case servicePaused:
		if err := m.checkedCommand(ctx, "systemctl", "thaw", linuxServiceUnitName); err != nil {
			return err
		}
		if err := m.waitForState(ctx, serviceRunning); err != nil {
			return err
		}
		return m.waitForReady(ctx)
	default:
		if err := m.checkedCommand(ctx, "systemctl", "start", linuxServiceUnitName); err != nil {
			return err
		}
		if err := m.waitForState(ctx, serviceRunning); err != nil {
			return err
		}
		return m.waitForReady(ctx)
	}
}

func (m *linuxServiceManager) Stop(ctx context.Context) error {
	status, err := m.Status(ctx)
	if err != nil {
		return err
	}
	switch status.State {
	case serviceNotInstalled, serviceStopped:
		return nil
	default:
		return m.checkedCommand(ctx, "systemctl", "stop", linuxServiceUnitName)
	}
}

func (m *linuxServiceManager) Status(ctx context.Context) (nativeServiceStatus, error) {
	_, err := os.Lstat(m.paths.unitFile)
	if errors.Is(err, os.ErrNotExist) {
		return nativeServiceStatus{State: serviceNotInstalled}, nil
	}
	if err != nil {
		return nativeServiceStatus{}, fmt.Errorf("airlock-host: inspect systemd unit: %w", err)
	}
	output, err := m.command(ctx, "systemctl", "show", linuxServiceUnitName, "--no-pager",
		"--property=LoadState", "--property=ActiveState", "--property=SubState",
		"--property=FreezerState", "--property=MainPID")
	if err != nil {
		return nativeServiceStatus{}, commandError("systemctl", output, err)
	}
	properties := make(map[string]string)
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			properties[key] = value
		}
	}
	if properties["LoadState"] == "not-found" {
		return nativeServiceStatus{State: serviceStopped}, nil
	}
	pid, err := strconv.ParseUint(properties["MainPID"], 10, 32)
	if err != nil && properties["MainPID"] != "" {
		return nativeServiceStatus{}, fmt.Errorf("airlock-host: parse systemd MainPID %q: %w", properties["MainPID"], err)
	}
	state := serviceUnknown
	if properties["FreezerState"] == "frozen" || properties["FreezerState"] == "freezing" {
		state = servicePaused
	} else {
		switch properties["ActiveState"] {
		case "active":
			state = serviceRunning
		case "activating", "reloading":
			state = serviceStartPending
		case "deactivating":
			state = serviceStopPending
		case "inactive", "failed":
			state = serviceStopped
		}
	}
	return nativeServiceStatus{State: state, PID: uint32(pid)}, nil
}

func (m *linuxServiceManager) Uninstall(ctx context.Context) error {
	_, err := os.Lstat(m.paths.unitFile)
	if errors.Is(err, os.ErrNotExist) {
		return m.checkedCommand(ctx, "systemctl", "daemon-reload")
	}
	if err != nil {
		return fmt.Errorf("airlock-host: inspect systemd unit: %w", err)
	}
	status, err := m.Status(ctx)
	if err != nil {
		return err
	}
	if status.State != serviceStopped && status.State != serviceNotInstalled {
		if err := m.checkedCommand(ctx, "systemctl", "stop", linuxServiceUnitName); err != nil {
			return err
		}
	}
	if err := m.checkedCommand(ctx, "systemctl", "disable", linuxServiceUnitName); err != nil {
		return err
	}
	if err := os.Remove(m.paths.unitFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("airlock-host: remove systemd unit: %w", err)
	}
	return m.checkedCommand(ctx, "systemctl", "daemon-reload")
}

func (m *linuxServiceManager) StateDirectory() string {
	return m.paths.stateDirectory
}

func (m *linuxServiceManager) waitForState(ctx context.Context, desired nativeServiceState) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := m.Status(ctx)
		if err != nil {
			return err
		}
		if status.State == desired {
			return nil
		}
		if desired == serviceRunning && status.State == serviceStopped {
			return errors.New("airlock-host: systemd service stopped before reaching running state")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (m *linuxServiceManager) waitForReady(parent context.Context) error {
	ready := m.ready
	if ready == nil {
		ready = linuxHostReady
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	return ready(ctx, m.paths.stateDirectory)
}

func linuxHostReady(ctx context.Context, stateDirectory string) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		client, err := connectorhost.NewLocalControlClient(stateDirectory)
		if err == nil {
			if _, err := client.Access(ctx); err == nil {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("airlock-host: wait for local control readiness: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (m *linuxServiceManager) createAccount(ctx context.Context) error {
	if err := m.checkedCommand(ctx, "groupadd", "--system", "--force", linuxServiceGroup); err != nil {
		return err
	}
	output, err := m.command(ctx, "id", "--user", linuxServiceUser)
	if err == nil {
		return m.validateAccount(ctx)
	}
	if exitCode(err) != 1 {
		return commandError("id", output, err)
	}
	if err := m.checkedCommand(ctx, "useradd", "--system", "--gid", linuxServiceGroup,
		"--home-dir", m.paths.stateDirectory, "--shell", "/usr/sbin/nologin",
		"--no-create-home", linuxServiceUser); err != nil {
		return err
	}
	return m.validateAccount(ctx)
}

func (m *linuxServiceManager) validateAccount(ctx context.Context) error {
	uidOutput, err := m.command(ctx, "id", "--user", linuxServiceUser)
	if err != nil {
		return commandError("id", uidOutput, err)
	}
	uid, err := strconv.ParseUint(strings.TrimSpace(string(uidOutput)), 10, 32)
	if err != nil || uid == 0 || uid >= 1000 {
		return errors.New("airlock-host: existing service account does not have a non-root system UID")
	}
	group, err := m.command(ctx, "id", "--group", "--name", linuxServiceUser)
	if err != nil {
		return commandError("id", group, err)
	}
	if strings.TrimSpace(string(group)) != linuxServiceGroup {
		return errors.New("airlock-host: existing service account does not use the airlock-host primary group")
	}
	record, err := m.command(ctx, "getent", "passwd", linuxServiceUser)
	if err != nil {
		return commandError("getent", record, err)
	}
	fields := strings.Split(strings.TrimSpace(string(record)), ":")
	if len(fields) != 7 || fields[0] != linuxServiceUser || fields[5] != m.paths.stateDirectory ||
		(fields[6] != "/usr/sbin/nologin" && fields[6] != "/sbin/nologin") {
		return errors.New("airlock-host: existing service account has unexpected home or shell settings")
	}
	passwdPath := m.passwdFile
	if passwdPath == "" {
		passwdPath = "/etc/passwd"
	}
	localRecords, err := os.ReadFile(passwdPath)
	if err != nil {
		return fmt.Errorf("airlock-host: read local account database: %w", err)
	}
	local := false
	for _, line := range strings.Split(string(localRecords), "\n") {
		if strings.HasPrefix(line, linuxServiceUser+":") {
			local = true
			break
		}
	}
	if !local {
		return errors.New("airlock-host: service account must be defined in the local account database")
	}
	passwordStatus, err := m.command(ctx, "passwd", "--status", linuxServiceUser)
	if err != nil {
		return commandError("passwd", passwordStatus, err)
	}
	statusFields := strings.Fields(string(passwordStatus))
	if len(statusFields) < 2 || statusFields[0] != linuxServiceUser || statusFields[1] != "L" {
		return errors.New("airlock-host: service account password must be locked")
	}
	return nil
}

func (m *linuxServiceManager) systemdUnit() string {
	arguments := []string{
		m.paths.executable,
		"--state-dir", m.paths.stateDirectory,
		"serve", "--control-port", strconv.Itoa(linuxControlPort),
	}
	for index := range arguments {
		arguments[index] = quoteSystemdArgument(arguments[index])
	}
	return "[Unit]\n" +
		"Description=" + nativeServiceDisplayName + "\n" +
		"After=network-online.target\n" +
		"Wants=network-online.target\n" +
		"\n" +
		"[Service]\n" +
		"Type=simple\n" +
		"User=" + linuxServiceUser + "\n" +
		"Group=" + linuxServiceGroup + "\n" +
		"ExecStart=" + strings.Join(arguments, " ") + "\n" +
		"Restart=on-failure\n" +
		"RestartSec=5s\n" +
		"\n" +
		"[Install]\n" +
		"WantedBy=multi-user.target\n"
}

func quoteSystemdArgument(argument string) string {
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"\"", "\\\"",
		"\n", "\\n",
		"\r", "\\r",
		"\t", "\\t",
		"$", "$$",
		"%", "%%",
	)
	return "\"" + replacer.Replace(argument) + "\""
}

func (m *linuxServiceManager) checkedCommand(ctx context.Context, name string, args ...string) error {
	output, err := m.command(ctx, name, args...)
	if err != nil {
		return commandError(name, output, err)
	}
	return nil
}

func (m *linuxServiceManager) reloadSystemd(ctx context.Context) error {
	output, err := m.command(ctx, "systemctl", "daemon-reload")
	if err == nil {
		return nil
	}
	message := string(output)
	if strings.Contains(message, "System has not been booted with systemd") || strings.Contains(message, "Failed to connect to bus") {
		return nil
	}
	return commandError("systemctl", output, err)
}

func (m *linuxServiceManager) command(ctx context.Context, name string, args ...string) ([]byte, error) {
	commandCtx, cancel := context.WithTimeout(ctx, m.commandTimeout)
	defer cancel()
	output, err := m.runCommand(commandCtx, name, args...)
	if commandCtx.Err() != nil {
		return output, commandCtx.Err()
	}
	return output, err
}

func commandError(name string, output []byte, err error) error {
	message := strings.TrimSpace(string(output))
	if message == "" {
		return fmt.Errorf("airlock-host: %s: %w", name, err)
	}
	return fmt.Errorf("airlock-host: %s: %s: %w", name, message, err)
}

func exitCode(err error) int {
	type exitCoder interface {
		ExitCode() int
	}
	var coder exitCoder
	if errors.As(err, &coder) {
		return coder.ExitCode()
	}
	return -1
}

func openRegularFile(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return file, nil
}

func copyExecutableIfNeeded(ctx context.Context, source *os.File, destination string) error {
	matches, err := fileMatches(ctx, source, destination, 0o755)
	if err != nil {
		return err
	}
	if matches {
		return nil
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return atomicWrite(ctx, destination, 0o755, func(target *os.File) error {
		buffer := make([]byte, 128*1024)
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			read, readErr := source.Read(buffer)
			if read > 0 {
				if _, err := target.Write(buffer[:read]); err != nil {
					return err
				}
			}
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			if readErr != nil {
				return readErr
			}
		}
	})
}

func writeFileIfNeeded(ctx context.Context, destination string, content []byte, mode os.FileMode) error {
	matches, err := fileMatchesBytes(ctx, destination, content, mode)
	if err != nil {
		return err
	}
	if matches {
		return nil
	}
	return atomicWrite(ctx, destination, mode, func(target *os.File) error {
		_, err := target.Write(content)
		return err
	})
}

func fileMatchesBytes(ctx context.Context, destination string, content []byte, mode os.FileMode) (bool, error) {
	target, err := openRegularFile(destination)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ELOOP) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer target.Close()
	info, err := target.Stat()
	if err != nil {
		return false, err
	}
	if !fileModeMatches(info.Mode(), mode) || info.Size() != int64(len(content)) {
		return false, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	existing, err := io.ReadAll(io.LimitReader(target, int64(len(content))+1))
	if err != nil {
		return false, err
	}
	return bytes.Equal(existing, content), nil
}

func fileMatches(ctx context.Context, source *os.File, destination string, mode os.FileMode) (bool, error) {
	target, err := openRegularFile(destination)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ELOOP) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer target.Close()
	sourceInfo, err := source.Stat()
	if err != nil {
		return false, err
	}
	targetInfo, err := target.Stat()
	if err != nil {
		return false, err
	}
	if !fileModeMatches(targetInfo.Mode(), mode) || sourceInfo.Size() != targetInfo.Size() {
		return false, nil
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	bufferSource := make([]byte, 128*1024)
	bufferTarget := make([]byte, len(bufferSource))
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		sourceRead, sourceErr := io.ReadFull(source, bufferSource)
		targetRead, targetErr := io.ReadFull(target, bufferTarget)
		if sourceRead != targetRead || !bytes.Equal(bufferSource[:sourceRead], bufferTarget[:targetRead]) {
			return false, nil
		}
		if errors.Is(sourceErr, io.EOF) && errors.Is(targetErr, io.EOF) {
			return true, nil
		}
		if errors.Is(sourceErr, io.ErrUnexpectedEOF) && errors.Is(targetErr, io.ErrUnexpectedEOF) {
			return true, nil
		}
		if sourceErr != nil || targetErr != nil {
			return false, errors.Join(sourceErr, targetErr)
		}
	}
}

func fileModeMatches(actual, expected os.FileMode) bool {
	const special = os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	return actual.Perm() == expected.Perm() && actual&special == 0
}

func atomicWrite(ctx context.Context, destination string, mode os.FileMode, write func(*os.File) error) (result error) {
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".airlock-host-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	temporaryOpen := true
	defer func() {
		if temporaryOpen {
			result = errors.Join(result, temporary.Close())
		}
		if temporaryPath != "" {
			result = errors.Join(result, os.Remove(temporaryPath))
		}
	}()
	if err := write(temporary); err != nil {
		return err
	}
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	temporaryOpen = false
	if err := os.Rename(temporaryPath, destination); err != nil {
		return err
	}
	temporaryPath = ""
	directory, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, directory.Close()) }()
	return directory.Sync()
}
