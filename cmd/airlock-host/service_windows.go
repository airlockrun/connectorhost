//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	connectorhost "github.com/airlockrun/connectorhost"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	nativeServiceSupported         = true
	windowsServiceMarker           = "__windows_service"
	windowsServiceControlPort      = 42927
	windowsServiceOperationTimeout = 30 * time.Second
	windowsServiceShutdownTimeout  = 25 * time.Second
	windowsServicePollInterval     = 200 * time.Millisecond
	windowsServiceDescription      = "Runs the Airlock connector host."
	windowsFileAllAccess           = windows.ACCESS_MASK(windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff)
	windowsFileReadExecute         = windows.ACCESS_MASK(windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE)
)

type windowsNativeServiceManager struct {
	executablePath string
	stateDirectory string
	timeout        time.Duration
}

type windowsServiceHandler struct {
	stateDirectory  string
	controlPort     int
	shutdownTimeout time.Duration
	run             func(context.Context, string, int) error
	ready           func(context.Context, string) error
	resultMu        sync.Mutex
	result          error
}

type windowsEventLogger interface {
	Info(uint32, string) error
	Warning(uint32, string) error
	Error(uint32, string) error
}

type windowsEventLogHandler struct {
	logger  windowsEventLogger
	options []windowsEventLogOption
}

type windowsEventLogOption struct {
	attributes []slog.Attr
	group      string
}

func (h *windowsEventLogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo
}

func (h *windowsEventLogHandler) Handle(ctx context.Context, record slog.Record) error {
	var output bytes.Buffer
	var handler slog.Handler = slog.NewTextHandler(&output, nil)
	for _, option := range h.options {
		if option.group != "" {
			handler = handler.WithGroup(option.group)
		} else {
			handler = handler.WithAttrs(option.attributes)
		}
	}
	if err := handler.Handle(ctx, record); err != nil {
		return err
	}
	message := strings.TrimSpace(output.String())
	if record.Level >= slog.LevelError {
		return h.logger.Error(1, message)
	}
	if record.Level >= slog.LevelWarn {
		return h.logger.Warning(1, message)
	}
	return h.logger.Info(1, message)
}

func (h *windowsEventLogHandler) WithAttrs(attributes []slog.Attr) slog.Handler {
	clone := *h
	clone.options = append(append([]windowsEventLogOption(nil), h.options...), windowsEventLogOption{attributes: append([]slog.Attr(nil), attributes...)})
	return &clone
}

func (h *windowsEventLogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	clone := *h
	clone.options = append(append([]windowsEventLogOption(nil), h.options...), windowsEventLogOption{group: name})
	return &clone
}

func newNativeServiceManager() (nativeServiceManager, error) {
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return nil, fmt.Errorf("airlock-host: locate Program Files: %w", err)
	}
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return nil, fmt.Errorf("airlock-host: locate ProgramData: %w", err)
	}
	return &windowsNativeServiceManager{
		executablePath: filepath.Join(programFiles, "Airlock", "airlock-host.exe"),
		stateDirectory: filepath.Join(programData, "Airlock", "Host"),
		timeout:        windowsServiceOperationTimeout,
	}, nil
}

func runNativeService(args []string) (bool, error) {
	if len(args) == 0 || args[0] != windowsServiceMarker {
		return false, nil
	}
	manager, err := newNativeServiceManager()
	if err != nil {
		return true, err
	}
	serviceManager := manager.(*windowsNativeServiceManager)
	if err := validateWindowsServiceArguments(args, serviceManager.stateDirectory); err != nil {
		return true, err
	}
	eventLogger, err := eventlog.Open(nativeServiceName)
	if err != nil {
		return true, fmt.Errorf("airlock-host: open Windows event log: %w", err)
	}
	defer eventLogger.Close()
	logger := slog.New(&windowsEventLogHandler{logger: eventLogger})
	handler := &windowsServiceHandler{
		stateDirectory:  serviceManager.stateDirectory,
		controlPort:     windowsServiceControlPort,
		shutdownTimeout: windowsServiceShutdownTimeout,
		run: func(ctx context.Context, stateDirectory string, controlPort int) error {
			return runHostWithLogger(ctx, stateDirectory, controlPort, logger)
		},
		ready: windowsHostReady,
	}
	if err := svc.Run(nativeServiceName, handler); err != nil {
		return true, fmt.Errorf("airlock-host: run Windows service: %w", err)
	}
	return true, handler.resultError()
}

func validateWindowsServiceArguments(args []string, stateDirectory string) error {
	if len(args) != 5 || args[0] != windowsServiceMarker || args[1] != "--state-dir" ||
		!strings.EqualFold(filepath.Clean(args[2]), filepath.Clean(stateDirectory)) ||
		args[3] != "--control-port" || args[4] != strconv.Itoa(windowsServiceControlPort) {
		return errors.New("airlock-host: invalid Windows service arguments")
	}
	return nil
}

func (h *windowsServiceHandler) Execute(args []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending, WaitHint: uint32((30 * time.Second) / time.Millisecond)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- h.run(ctx, h.stateDirectory, h.controlPort) }()
	ready := h.ready
	if ready == nil {
		ready = windowsHostReady
	}
	startupCtx, startupCancel := context.WithTimeout(ctx, windowsServiceOperationTimeout)
	readyResult := make(chan error, 1)
	go func() { readyResult <- ready(startupCtx, h.stateDirectory) }()
	checkpoint := uint32(1)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-result:
			startupCancel()
			h.setResult(err)
			if err != nil {
				return false, uint32(windows.ERROR_EXCEPTION_IN_SERVICE)
			}
			return false, 0
		case err := <-readyResult:
			startupCancel()
			if err != nil {
				cancel()
				h.setResult(err)
				return false, uint32(windows.ERROR_EXCEPTION_IN_SERVICE)
			}
			goto running
		case <-ticker.C:
			checkpoint++
			statuses <- svc.Status{State: svc.StartPending, CheckPoint: checkpoint, WaitHint: uint32(windowsServiceOperationTimeout / time.Millisecond)}
		}
	}

running:
	accepted := svc.AcceptStop | svc.AcceptShutdown
	current := svc.Status{State: svc.Running, Accepts: accepted}
	statuses <- current
	for {
		select {
		case err := <-result:
			h.setResult(err)
			if err != nil {
				return false, uint32(windows.ERROR_EXCEPTION_IN_SERVICE)
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				statuses <- current
			case svc.Stop, svc.Shutdown:
				cancel()
				err := h.waitForShutdown(requests, statuses, result)
				h.setResult(err)
				if err == nil {
					return false, 0
				}
				if errors.Is(err, context.DeadlineExceeded) {
					return false, uint32(windows.ERROR_SERVICE_REQUEST_TIMEOUT)
				}
				return false, uint32(windows.ERROR_EXCEPTION_IN_SERVICE)
			}
		}
	}
}

func windowsHostReady(ctx context.Context, stateDirectory string) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		descriptor, descriptorErr := connectorhost.ReadControlDescriptor(stateDirectory)
		if descriptorErr == nil && descriptor.PID == os.Getpid() {
			client, err := connectorhost.NewLocalControlClient(stateDirectory)
			if err == nil {
				if _, err := client.Access(ctx); err == nil {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("airlock-host: wait for local control readiness: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (h *windowsServiceHandler) setResult(err error) {
	h.resultMu.Lock()
	h.result = err
	h.resultMu.Unlock()
	if err != nil {
		logger, openErr := eventlog.Open(nativeServiceName)
		if openErr == nil {
			_ = logger.Error(1, err.Error())
			_ = logger.Close()
		}
	}
}

func (h *windowsServiceHandler) resultError() error {
	h.resultMu.Lock()
	defer h.resultMu.Unlock()
	return h.result
}

func (h *windowsServiceHandler) waitForShutdown(requests <-chan svc.ChangeRequest, statuses chan<- svc.Status, result <-chan error) error {
	timeout := h.shutdownTimeout
	if timeout <= 0 {
		timeout = windowsServiceShutdownTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	checkpoint := uint32(1)
	pending := func() svc.Status {
		return svc.Status{State: svc.StopPending, CheckPoint: checkpoint, WaitHint: uint32(timeout / time.Millisecond)}
	}
	statuses <- pending()
	for {
		select {
		case err := <-result:
			return err
		case <-timer.C:
			return context.DeadlineExceeded
		case <-ticker.C:
			checkpoint++
			statuses <- pending()
		case request := <-requests:
			if request.Cmd == svc.Interrogate {
				statuses <- pending()
			}
		}
	}
}

func (m *windowsNativeServiceManager) StateDirectory() string { return m.stateDirectory }

func (m *windowsNativeServiceManager) Install(parent context.Context) (err error) {
	ctx, cancel := m.operationContext(parent)
	defer cancel()
	source, err := os.Executable()
	if err != nil {
		return fmt.Errorf("airlock-host: locate executable: %w", err)
	}
	source, err = filepath.Abs(source)
	if err != nil {
		return fmt.Errorf("airlock-host: resolve executable: %w", err)
	}
	if err := validateExecutable(source); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("airlock-host: connect to Windows service manager: %w", err)
	}
	defer manager.Disconnect()

	service, openErr := manager.OpenService(nativeServiceName)
	created := false
	if openErr == nil {
		config, err := service.Config()
		if err != nil {
			service.Close()
			return fmt.Errorf("airlock-host: read existing Windows service: %w", err)
		}
		if conflict := windowsServiceConfigConflict(config, m.executablePath, m.stateDirectory); conflict != "" {
			service.Close()
			return fmt.Errorf("airlock-host: existing %s service conflicts on %s", nativeServiceName, conflict)
		}
		needsInstall, err := windowsExecutableNeedsInstall(source, m.executablePath)
		if err != nil {
			service.Close()
			return fmt.Errorf("airlock-host: inspect installed executable: %w", err)
		}
		if needsInstall {
			if err := stopWindowsService(ctx, service); err != nil {
				service.Close()
				return err
			}
		}
	} else if errors.Is(openErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		service, err = manager.CreateService(nativeServiceName, m.executablePath, windowsServiceConfig(m.executablePath, m.stateDirectory), windowsServiceArguments(m.stateDirectory)...)
		if err != nil {
			return fmt.Errorf("airlock-host: create Windows service: %w", err)
		}
		created = true
	} else {
		return fmt.Errorf("airlock-host: open Windows service: %w", openErr)
	}
	defer service.Close()
	if created {
		defer func() {
			if err != nil {
				_ = service.Delete()
			}
		}()
	}
	eventSourceCreated, err := ensureWindowsEventSource()
	if err != nil {
		return fmt.Errorf("airlock-host: install Windows event source: %w", err)
	}
	if eventSourceCreated {
		defer func() {
			if err != nil {
				_ = eventlog.Remove(nativeServiceName)
			}
		}()
	}

	serviceSID, _, _, err := windows.LookupSID("", `NT SERVICE\`+nativeServiceName)
	if err != nil {
		return fmt.Errorf("airlock-host: resolve Windows service SID: %w", err)
	}
	if err := provisionWindowsServiceState(m.stateDirectory, serviceSID); err != nil {
		return fmt.Errorf("airlock-host: protect service state: %w", err)
	}
	if err := installWindowsExecutable(source, m.executablePath, serviceSID); err != nil {
		return fmt.Errorf("airlock-host: install executable: %w", err)
	}
	return ctx.Err()
}

func (m *windowsNativeServiceManager) Start(parent context.Context) error {
	ctx, cancel := m.operationContext(parent)
	defer cancel()
	manager, service, err := openWindowsService()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	defer service.Close()
	return startWindowsService(ctx, service)
}

func (m *windowsNativeServiceManager) Stop(parent context.Context) error {
	ctx, cancel := m.operationContext(parent)
	defer cancel()
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("airlock-host: connect to Windows service manager: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(nativeServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) || errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("airlock-host: open Windows service: %w", err)
	}
	defer service.Close()
	return stopWindowsService(ctx, service)
}

func (m *windowsNativeServiceManager) Status(parent context.Context) (nativeServiceStatus, error) {
	ctx, cancel := m.operationContext(parent)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nativeServiceStatus{}, err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return nativeServiceStatus{}, fmt.Errorf("airlock-host: connect to Windows service manager: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(nativeServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) || errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return nativeServiceStatus{State: serviceNotInstalled}, nil
	}
	if err != nil {
		return nativeServiceStatus{}, fmt.Errorf("airlock-host: open Windows service: %w", err)
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return nativeServiceStatus{}, fmt.Errorf("airlock-host: query Windows service: %w", err)
	}
	return nativeServiceStatus{
		State:                   nativeStateFromWindows(status.State),
		PID:                     status.ProcessId,
		Win32ExitCode:           status.Win32ExitCode,
		ServiceSpecificExitCode: status.ServiceSpecificExitCode,
	}, nil
}

func (m *windowsNativeServiceManager) Uninstall(parent context.Context) error {
	ctx, cancel := m.operationContext(parent)
	defer cancel()
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("airlock-host: connect to Windows service manager: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(nativeServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return removeWindowsEventSource()
	}
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return removeWindowsEventSource()
	}
	if err != nil {
		return fmt.Errorf("airlock-host: open Windows service: %w", err)
	}
	config, err := service.Config()
	if err != nil {
		service.Close()
		return fmt.Errorf("airlock-host: read Windows service configuration: %w", err)
	}
	if conflict := windowsServiceConfigConflict(config, m.executablePath, m.stateDirectory); conflict != "" {
		service.Close()
		return fmt.Errorf("airlock-host: refusing to uninstall conflicting %s service (%s)", nativeServiceName, conflict)
	}
	if err := stopWindowsService(ctx, service); err != nil {
		service.Close()
		return err
	}
	if err := service.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		service.Close()
		return fmt.Errorf("airlock-host: delete Windows service: %w", err)
	}
	if err := service.Close(); err != nil {
		return fmt.Errorf("airlock-host: close Windows service: %w", err)
	}
	if err := waitWindowsServiceDeleted(ctx, manager); err != nil {
		return err
	}
	return removeWindowsEventSource()
}

func (m *windowsNativeServiceManager) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	timeout := m.timeout
	if timeout <= 0 {
		timeout = windowsServiceOperationTimeout
	}
	return context.WithTimeout(parent, timeout)
}

func windowsServiceArguments(stateDirectory string) []string {
	return []string{windowsServiceMarker, "--state-dir", stateDirectory, "--control-port", strconv.Itoa(windowsServiceControlPort)}
}

func windowsServiceConfig(executablePath, stateDirectory string) mgr.Config {
	return mgr.Config{
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:        mgr.StartAutomatic,
		ErrorControl:     mgr.ErrorNormal,
		BinaryPathName:   windowsServiceCommandLine(executablePath, stateDirectory),
		ServiceStartName: `NT SERVICE\` + nativeServiceName,
		DisplayName:      nativeServiceDisplayName,
		Description:      windowsServiceDescription,
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
		DelayedAutoStart: true,
	}
}

func windowsServiceCommandLine(executablePath, stateDirectory string) string {
	commandLine := syscall.EscapeArg(executablePath)
	for _, argument := range windowsServiceArguments(stateDirectory) {
		commandLine += " " + syscall.EscapeArg(argument)
	}
	return commandLine
}

func windowsServiceConfigConflict(config mgr.Config, executablePath, stateDirectory string) string {
	expected := windowsServiceConfig(executablePath, stateDirectory)
	if !strings.EqualFold(config.BinaryPathName, expected.BinaryPathName) {
		return "binary path or arguments"
	}
	if config.ServiceType != expected.ServiceType {
		return "service type"
	}
	if config.StartType != expected.StartType || !config.DelayedAutoStart {
		return "automatic delayed start"
	}
	if config.ErrorControl != expected.ErrorControl {
		return "error control"
	}
	if !strings.EqualFold(config.ServiceStartName, expected.ServiceStartName) {
		return "service account"
	}
	if config.SidType != expected.SidType {
		return "service SID type"
	}
	if config.DisplayName != expected.DisplayName {
		return "display name"
	}
	return ""
}

func openWindowsService() (*mgr.Mgr, *mgr.Service, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return nil, nil, fmt.Errorf("airlock-host: connect to Windows service manager: %w", err)
	}
	service, err := manager.OpenService(nativeServiceName)
	if err != nil {
		manager.Disconnect()
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil, nil, errors.New("airlock-host: Windows service is not installed")
		}
		return nil, nil, fmt.Errorf("airlock-host: open Windows service: %w", err)
	}
	return manager, service, nil
}

func startWindowsService(ctx context.Context, service *mgr.Service) error {
	status, err := service.Query()
	if err != nil {
		return fmt.Errorf("airlock-host: query Windows service: %w", err)
	}
	for {
		switch status.State {
		case svc.Running:
			return nil
		case svc.StartPending:
			return waitWindowsServiceState(ctx, service, svc.Running)
		case svc.StopPending:
			if _, err := waitWindowsServiceStateStatus(ctx, service, svc.Stopped); err != nil {
				return err
			}
			status.State = svc.Stopped
		case svc.Paused:
			if _, err := service.Control(svc.Continue); err != nil {
				return fmt.Errorf("airlock-host: continue Windows service: %w", err)
			}
			return waitWindowsServiceState(ctx, service, svc.Running)
		case svc.Stopped:
			if err := service.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
				return fmt.Errorf("airlock-host: start Windows service: %w", err)
			}
			return waitWindowsServiceState(ctx, service, svc.Running)
		default:
			return fmt.Errorf("airlock-host: cannot start Windows service from state %d", status.State)
		}
	}
}

func stopWindowsService(ctx context.Context, service *mgr.Service) error {
	status, err := service.Query()
	if err != nil {
		return fmt.Errorf("airlock-host: query Windows service: %w", err)
	}
	if status.State == svc.Stopped {
		return nil
	}
	if status.State == svc.StopPending {
		return waitWindowsServiceState(ctx, service, svc.Stopped)
	}
	if status.State == svc.StartPending {
		status, err = waitWindowsServiceStateStatus(ctx, service, svc.Running)
		if err != nil {
			return err
		}
	}
	if status.State != svc.Running && status.State != svc.Paused {
		return fmt.Errorf("airlock-host: cannot stop Windows service from state %d", status.State)
	}
	if _, err := service.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return fmt.Errorf("airlock-host: stop Windows service: %w", err)
	}
	return waitWindowsServiceState(ctx, service, svc.Stopped)
}

func waitWindowsServiceState(ctx context.Context, service *mgr.Service, desired svc.State) error {
	_, err := waitWindowsServiceStateStatus(ctx, service, desired)
	return err
}

func waitWindowsServiceStateStatus(ctx context.Context, service *mgr.Service, desired svc.State) (svc.Status, error) {
	ticker := time.NewTicker(windowsServicePollInterval)
	defer ticker.Stop()
	for {
		status, err := service.Query()
		if err != nil {
			return svc.Status{}, fmt.Errorf("airlock-host: query Windows service: %w", err)
		}
		if status.State == desired {
			return status, nil
		}
		if desired == svc.Running && status.State == svc.Stopped {
			return svc.Status{}, fmt.Errorf("airlock-host: Windows service stopped before reaching running state (win32=%d, service=%d)", status.Win32ExitCode, status.ServiceSpecificExitCode)
		}
		select {
		case <-ctx.Done():
			return svc.Status{}, fmt.Errorf("airlock-host: wait for Windows service state %d: %w", desired, ctx.Err())
		case <-ticker.C:
		}
	}
}

func waitWindowsServiceDeleted(ctx context.Context, manager *mgr.Mgr) error {
	ticker := time.NewTicker(windowsServicePollInterval)
	defer ticker.Stop()
	for {
		service, err := manager.OpenService(nativeServiceName)
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		if err == nil {
			service.Close()
		} else if !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			return fmt.Errorf("airlock-host: wait for Windows service deletion: %w", err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("airlock-host: wait for Windows service deletion: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func nativeStateFromWindows(state svc.State) nativeServiceState {
	switch state {
	case svc.Stopped:
		return serviceStopped
	case svc.StartPending:
		return serviceStartPending
	case svc.StopPending:
		return serviceStopPending
	case svc.Running:
		return serviceRunning
	case svc.Paused, svc.PausePending, svc.ContinuePending:
		return servicePaused
	default:
		return serviceUnknown
	}
}

func provisionWindowsServiceState(root string, serviceSID *windows.SID) error {
	parent := filepath.Dir(root)
	if err := validateExistingWindowsDirectoryOwner(parent); err != nil {
		return err
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	if err := rejectWindowsReparsePoint(parent); err != nil {
		return err
	}
	if err := setWindowsServicePathACL(parent, true, serviceSID, windowsFileAllAccess); err != nil {
		return err
	}
	if err := validateExistingWindowsDirectoryOwner(root); err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := rejectWindowsReparsePoint(path); err != nil {
			return err
		}
		return setWindowsServicePathACL(path, entry.IsDir(), serviceSID, windowsFileAllAccess)
	})
}

func installWindowsExecutable(source, target string, serviceSID *windows.SID) error {
	if err := validateExecutable(source); err != nil {
		return err
	}
	directory := filepath.Dir(target)
	if err := validateExistingWindowsDirectoryOwner(directory); err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	if err := rejectWindowsReparsePoint(directory); err != nil {
		return err
	}
	if err := setWindowsServicePathACL(directory, true, serviceSID, windowsFileReadExecute); err != nil {
		return err
	}
	if strings.EqualFold(filepath.Clean(source), filepath.Clean(target)) {
		return setWindowsServicePathACL(target, false, serviceSID, windowsFileReadExecute)
	}
	if _, err := os.Stat(target); err == nil {
		equal, err := filesEqual(source, target)
		if err != nil {
			return err
		}
		if equal {
			return setWindowsServicePathACL(target, false, serviceSID, windowsFileReadExecute)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	temporary, err := os.CreateTemp(directory, ".airlock-host-*.exe")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := io.Copy(temporary, input); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := validateExecutable(temporaryPath); err != nil {
		return err
	}
	if err := setWindowsServicePathACL(temporaryPath, false, serviceSID, windowsFileReadExecute); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(temporaryPath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return err
	}
	return setWindowsServicePathACL(target, false, serviceSID, windowsFileReadExecute)
}

func windowsExecutableNeedsInstall(source, target string) (bool, error) {
	if err := rejectWindowsReparsePoint(filepath.Dir(target)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, err
	}
	if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
		return true, nil
	} else if err != nil {
		return false, err
	}
	if err := rejectWindowsReparsePoint(target); err != nil {
		return false, err
	}
	equal, err := filesEqual(source, target)
	return !equal, err
}

func validateExecutable(path string) error {
	if !strings.EqualFold(filepath.Ext(path), ".exe") {
		return fmt.Errorf("airlock-host: executable %q does not have an .exe extension", path)
	}
	if err := rejectWindowsReparsePoint(path); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("airlock-host: executable %q is not a regular file", path)
	}
	image, err := pe.Open(path)
	if err != nil {
		return fmt.Errorf("airlock-host: validate PE executable %q: %w", path, err)
	}
	defer image.Close()
	if image.FileHeader.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
		return fmt.Errorf("airlock-host: PE image %q is not executable", path)
	}
	return nil
}

func rejectWindowsReparsePoint(path string) error {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(pointer)
	if err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("airlock-host: refusing reparse point %q", path)
	}
	return nil
}

func setWindowsServicePathACL(path string, directory bool, serviceSID *windows.SID, serviceAccess windows.ACCESS_MASK) error {
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	entries := []windows.EXPLICIT_ACCESS{
		windowsExplicitAccess(serviceSID, serviceAccess, inheritance),
		windowsExplicitAccess(administrators, windowsFileAllAccess, inheritance),
		windowsExplicitAccess(system, windowsFileAllAccess, inheritance),
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION, administrators, nil, acl, nil)
}

func validateExistingWindowsDirectoryOwner(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("airlock-host: service path %q is not a directory", path)
	}
	if err := rejectWindowsReparsePoint(path); err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return fmt.Errorf("airlock-host: service directory %q has an untrusted owner", path)
	}
	return nil
}

func ensureWindowsEventSource() (bool, error) {
	const path = `SYSTEM\CurrentControlSet\Services\EventLog\Application\AirlockHost`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
	if err == nil {
		_ = key.Close()
		return false, nil
	}
	if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return false, err
	}
	if err := eventlog.InstallAsEventCreate(nativeServiceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		return false, err
	}
	return true, nil
}

func removeWindowsEventSource() error {
	err := eventlog.Remove(nativeServiceName)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	return err
}

func windowsExplicitAccess(sid *windows.SID, access windows.ACCESS_MASK, inheritance uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: access,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func filesEqual(left, right string) (bool, error) {
	leftHash, err := fileSHA256(left)
	if err != nil {
		return false, err
	}
	rightHash, err := fileSHA256(right)
	if err != nil {
		return false, err
	}
	return leftHash == rightHash, nil
}

func fileSHA256(path string) ([sha256.Size]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return [sha256.Size]byte{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

var _ svc.Handler = (*windowsServiceHandler)(nil)
var _ nativeServiceManager = (*windowsNativeServiceManager)(nil)
