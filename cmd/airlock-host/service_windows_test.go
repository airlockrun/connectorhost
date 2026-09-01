//go:build windows

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	connectorhost "github.com/airlockrun/connectorhost"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type recordingWindowsEventLogger struct {
	info     []string
	warnings []string
	errors   []string
}

func (l *recordingWindowsEventLogger) Info(_ uint32, message string) error {
	l.info = append(l.info, message)
	return nil
}

func (l *recordingWindowsEventLogger) Warning(_ uint32, message string) error {
	l.warnings = append(l.warnings, message)
	return nil
}

func (l *recordingWindowsEventLogger) Error(_ uint32, message string) error {
	l.errors = append(l.errors, message)
	return nil
}

func TestWindowsEventLogHandlerPreservesSeverity(t *testing.T) {
	recorder := &recordingWindowsEventLogger{}
	logger := slog.New(&windowsEventLogHandler{logger: recorder})
	logger.Info("started", "version", "test")
	logger.Warn("sync failed")
	logger.Error("stopped")
	if len(recorder.info) != 1 || !strings.Contains(recorder.info[0], "version=test") {
		t.Fatalf("info events = %q", recorder.info)
	}
	if len(recorder.warnings) != 1 || !strings.Contains(recorder.warnings[0], "sync failed") {
		t.Fatalf("warning events = %q", recorder.warnings)
	}
	if len(recorder.errors) != 1 || !strings.Contains(recorder.errors[0], "stopped") {
		t.Fatalf("error events = %q", recorder.errors)
	}
}

func TestWindowsServiceArguments(t *testing.T) {
	stateDirectory := `C:\ProgramData\Airlock\Host`
	arguments := windowsServiceArguments(stateDirectory)
	if err := validateWindowsServiceArguments(arguments, stateDirectory); err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsServiceArguments(append(arguments, "unexpected"), stateDirectory); err == nil {
		t.Fatal("extra service argument was accepted")
	}
	if err := validateWindowsServiceArguments([]string{windowsServiceMarker, "--state-dir", stateDirectory, "--control-port", "1"}, stateDirectory); err == nil {
		t.Fatal("unexpected control port was accepted")
	}
}

func TestWindowsServiceConfigContract(t *testing.T) {
	executable := `C:\Program Files\Airlock\airlock-host.exe`
	stateDirectory := `C:\ProgramData\Airlock\Host`
	config := windowsServiceConfig(executable, stateDirectory)
	if conflict := windowsServiceConfigConflict(config, executable, stateDirectory); conflict != "" {
		t.Fatalf("matching configuration conflicts on %s", conflict)
	}
	if config.ServiceStartName != `NT SERVICE\AirlockHost` {
		t.Fatalf("service account = %q", config.ServiceStartName)
	}
	if !config.DelayedAutoStart || config.SidType != windows.SERVICE_SID_TYPE_UNRESTRICTED {
		t.Fatalf("delayed start = %t, SID type = %d", config.DelayedAutoStart, config.SidType)
	}
	wantCommandLine := `"C:\Program Files\Airlock\airlock-host.exe" __windows_service --state-dir C:\ProgramData\Airlock\Host --control-port 42927`
	if config.BinaryPathName != wantCommandLine {
		t.Fatalf("binary path = %q, want %q", config.BinaryPathName, wantCommandLine)
	}

	tests := []struct {
		name   string
		mutate func(*mgr.Config)
		want   string
	}{
		{name: "binary", mutate: func(config *mgr.Config) { config.BinaryPathName += " --extra" }, want: "binary path or arguments"},
		{name: "account", mutate: func(config *mgr.Config) { config.ServiceStartName = "LocalSystem" }, want: "service account"},
		{name: "start", mutate: func(config *mgr.Config) { config.DelayedAutoStart = false }, want: "automatic delayed start"},
		{name: "sid", mutate: func(config *mgr.Config) { config.SidType = windows.SERVICE_SID_TYPE_NONE }, want: "service SID type"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := config
			test.mutate(&actual)
			if got := windowsServiceConfigConflict(actual, executable, stateDirectory); got != test.want {
				t.Fatalf("conflict = %q, want %q", got, test.want)
			}
		})
	}
}

func TestWindowsServiceHandlerStopAndInterrogate(t *testing.T) {
	runStarted := make(chan struct{})
	handler := &windowsServiceHandler{
		stateDirectory:  `C:\ProgramData\Airlock\Host`,
		controlPort:     windowsServiceControlPort,
		shutdownTimeout: time.Second,
		ready:           func(context.Context, string) error { return nil },
		run: func(ctx context.Context, stateDirectory string, controlPort int) error {
			if stateDirectory != `C:\ProgramData\Airlock\Host` || controlPort != windowsServiceControlPort {
				return errors.New("unexpected host arguments")
			}
			close(runStarted)
			<-ctx.Done()
			return nil
		},
	}
	requests := make(chan svc.ChangeRequest, 2)
	statuses := make(chan svc.Status, 8)
	result := make(chan struct {
		serviceSpecific bool
		exitCode        uint32
	}, 1)
	go func() {
		serviceSpecific, exitCode := handler.Execute([]string{nativeServiceName}, requests, statuses)
		result <- struct {
			serviceSpecific bool
			exitCode        uint32
		}{serviceSpecific: serviceSpecific, exitCode: exitCode}
	}()

	assertWindowsServiceStatus(t, statuses, svc.StartPending)
	assertWindowsServiceStatus(t, statuses, svc.Running)
	<-runStarted
	requests <- svc.ChangeRequest{Cmd: svc.Interrogate}
	assertWindowsServiceStatus(t, statuses, svc.Running)
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	assertWindowsServiceStatus(t, statuses, svc.StopPending)
	select {
	case got := <-result:
		if got.serviceSpecific || got.exitCode != 0 {
			t.Fatalf("handler result = (%t, %d)", got.serviceSpecific, got.exitCode)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not stop")
	}
}

func TestWindowsServiceHandlerShutdownIsBounded(t *testing.T) {
	release := make(chan struct{})
	handler := &windowsServiceHandler{
		stateDirectory:  `C:\ProgramData\Airlock\Host`,
		controlPort:     windowsServiceControlPort,
		shutdownTimeout: 20 * time.Millisecond,
		ready:           func(context.Context, string) error { return nil },
		run: func(context.Context, string, int) error {
			<-release
			return nil
		},
	}
	requests := make(chan svc.ChangeRequest, 1)
	statuses := make(chan svc.Status, 4)
	result := make(chan uint32, 1)
	go func() {
		_, exitCode := handler.Execute([]string{nativeServiceName}, requests, statuses)
		result <- exitCode
	}()
	assertWindowsServiceStatus(t, statuses, svc.StartPending)
	assertWindowsServiceStatus(t, statuses, svc.Running)
	requests <- svc.ChangeRequest{Cmd: svc.Shutdown}
	assertWindowsServiceStatus(t, statuses, svc.StopPending)
	select {
	case exitCode := <-result:
		if exitCode != uint32(windows.ERROR_SERVICE_REQUEST_TIMEOUT) {
			t.Fatalf("exit code = %d", exitCode)
		}
	case <-time.After(time.Second):
		t.Fatal("handler shutdown was not bounded")
	}
	close(release)
}

func TestWindowsServiceStateACL(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(filepath.Join(root, "connectors"), 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "connectors", "state.json")
	if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	serviceSID := user.User.Sid
	if err := setWindowsServicePathACL(filepath.Dir(root), true, serviceSID, windowsFileAllAccess); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsServicePathACL(root, true, serviceSID, windowsFileAllAccess); err != nil {
		t.Fatal(err)
	}
	if err := provisionWindowsServiceState(root, serviceSID); err != nil {
		t.Fatal(err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	assertWindowsProtectedACL(t, root, map[string]windows.ACCESS_MASK{
		serviceSID.String():     windowsFileAllAccess,
		administrators.String(): windowsFileAllAccess,
		system.String():         windowsFileAllAccess,
	}, true)
	assertWindowsProtectedACL(t, file, map[string]windows.ACCESS_MASK{
		serviceSID.String():     windowsFileAllAccess,
		administrators.String(): windowsFileAllAccess,
		system.String():         windowsFileAllAccess,
	}, false)
}

func TestWindowsConnectorHostFilesAllowElevatedCLI(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := connectorhost.OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server, err := connectorhost.NewLocalControlServer(connectorhost.NewHost(store, nil, slog.New(slog.NewTextHandler(io.Discard, nil))), 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(ctx) }()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	want := make(map[string]windows.ACCESS_MASK)
	for _, sid := range []*windows.SID{user.User.Sid, administrators, system} {
		want[sid.String()] = windowsFileAllAccess
	}
	assertWindowsProtectedACL(t, root, want, true)
	assertWindowsProtectedACL(t, filepath.Join(root, "host.json"), want, false)
	assertWindowsProtectedACL(t, filepath.Join(root, "control.json"), want, false)
	cancel()
	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("control server did not stop")
	}
}

func TestWindowsSCMServiceLifecycle(t *testing.T) {
	if os.Getenv("AIRLOCK_TEST_WINDOWS_SCM") != "1" {
		t.Skip("set AIRLOCK_TEST_WINDOWS_SCM=1 on an isolated Windows machine")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_TEMP") == "" {
		t.Fatal("native SCM test is restricted to an isolated GitHub Actions runner")
	}
	managerValue, err := newNativeServiceManager()
	if err != nil {
		t.Fatal(err)
	}
	manager := managerValue.(*windowsNativeServiceManager)
	buildDirectory := t.TempDir()
	binary := filepath.Join(buildDirectory, "airlock-host.exe")
	command := exec.Command("go", "build", "-trimpath", "-o", binary, ".")
	command.Env = append(os.Environ(), "GOWORK=off")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build service binary: %v: %s", err, output)
	}
	runBinary := func(executable string, arguments ...string) string {
		t.Helper()
		command := exec.Command(executable, arguments...)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("airlock-host %s: %v: %s", strings.Join(arguments, " "), err, output)
		}
		return strings.TrimSpace(string(output))
	}
	runService := func(executable string, arguments ...string) string {
		t.Helper()
		return runBinary(executable, append([]string{"service"}, arguments...)...)
	}
	cleanup := func() {
		command := exec.Command(binary, "service", "uninstall")
		_, _ = command.CombinedOutput()
		_ = os.Remove(manager.executablePath)
		_ = os.RemoveAll(manager.stateDirectory)
	}
	cleanup()
	t.Cleanup(cleanup)

	if output := runService(binary, "install"); !strings.HasPrefix(output, "installed\nNext:\n") {
		t.Fatalf("install output = %q", output)
	}
	serviceSID, _, _, err := windows.LookupSID("", `NT SERVICE\`+nativeServiceName)
	if err != nil {
		t.Fatal(err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	wantStateACL := map[string]windows.ACCESS_MASK{
		serviceSID.String():     windowsFileAllAccess,
		administrators.String(): windowsFileAllAccess,
		system.String():         windowsFileAllAccess,
	}
	assertWindowsProtectedACL(t, filepath.Dir(manager.stateDirectory), wantStateACL, true)
	assertWindowsProtectedACL(t, manager.stateDirectory, wantStateACL, true)
	assertWindowsOwner(t, filepath.Dir(manager.stateDirectory), windows.WinBuiltinAdministratorsSid)
	assertWindowsOwner(t, manager.stateDirectory, windows.WinBuiltinAdministratorsSid)

	if output := runService(binary, "start"); output != "running" {
		t.Fatalf("start output = %q", output)
	}
	if output := runService(binary, "status"); !strings.HasPrefix(output, "running\t") {
		t.Fatalf("status output = %q", output)
	}
	helperSource := filepath.Join(buildDirectory, "connector.go")
	helperBinary := filepath.Join(buildDirectory, "private-connector.exe")
	helperCode := `package main

import (
	"fmt"
	"os"

	"github.com/airlockrun/agentsdk/connector"
)

func main() {
	runtime := connector.New(connector.Config{
		Kind: "scm-test",
		Contract: connector.DefineContract("io.airlockrun.connectorhost_scm_test"),
		Name: "SCM test connector",
		Description: "Exercises service-account artifact streaming.",
		ArtifactVersion: "1",
		Targets: []string{connector.PlatformWindowsAMD64},
	})
	if err := runtime.Run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
`
	if err := os.WriteFile(helperSource, []byte(helperCode), 0o600); err != nil {
		t.Fatal(err)
	}
	command = exec.Command("go", "build", "-trimpath", "-o", helperBinary, helperSource)
	command.Env = append(os.Environ(), "GOWORK=off")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build private connector: %v: %s", err, output)
	}
	installationID := runBinary(binary, "--state-dir", manager.stateDirectory, "connector", "install", helperBinary)
	if installationID == "" {
		t.Fatal("connector installation returned no ID")
	}
	status := runBinary(binary, "--state-dir", manager.stateDirectory, "connector", "status", installationID)
	if !strings.Contains(status, "SCM test connector") {
		t.Fatalf("connector status = %q", status)
	}

	upgradeBinary := filepath.Join(buildDirectory, "airlock-host-upgrade.exe")
	body, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, []byte("upgrade-test")...)
	if err := os.WriteFile(upgradeBinary, body, 0o700); err != nil {
		t.Fatal(err)
	}
	if output := runService(upgradeBinary, "install"); !strings.HasPrefix(output, "installed\nNext:\n") {
		t.Fatalf("upgrade install output = %q", output)
	}
	if output := runService(upgradeBinary, "start"); output != "running" {
		t.Fatalf("upgraded start output = %q", output)
	}
	if output := runService(binary, "stop"); output != "stopped" {
		t.Fatalf("stop output = %q", output)
	}
	if output := runBinary(binary, "--state-dir", manager.stateDirectory, "access", "get"); output != "full" {
		t.Fatalf("direct stopped-service access output = %q", output)
	}
	if output := runService(binary, "start"); output != "running" {
		t.Fatalf("restart after direct access output = %q", output)
	}
	if output := runService(binary, "stop"); output != "stopped" {
		t.Fatalf("second stop output = %q", output)
	}
	if err := os.WriteFile(manager.executablePath, []byte("corrupt"), 0o700); err != nil {
		t.Fatal(err)
	}
	if output := runService(binary, "install"); !strings.HasPrefix(output, "installed\nNext:\n") {
		t.Fatalf("repair install output = %q", output)
	}
	if err := validateExecutable(manager.executablePath); err != nil {
		t.Fatalf("repaired executable: %v", err)
	}
	if output := runService(binary, "uninstall"); output != "uninstalled" {
		t.Fatalf("uninstall output = %q", output)
	}
	if status, err := manager.Status(t.Context()); err != nil || status.State != serviceNotInstalled {
		t.Fatalf("status after uninstall = %+v, %v", status, err)
	}
}

func assertWindowsOwner(t *testing.T, path string, want windows.WELL_KNOWN_SID_TYPE) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if !owner.IsWellKnown(want) {
		t.Fatalf("owner for %q = %s", path, owner.String())
	}
}

func assertWindowsServiceStatus(t *testing.T, statuses <-chan svc.Status, want svc.State) {
	t.Helper()
	select {
	case status := <-statuses:
		if status.State != want {
			t.Fatalf("service state = %d, want %d", status.State, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for service state %d", want)
	}
}

func assertWindowsProtectedACL(t *testing.T, path string, want map[string]windows.ACCESS_MASK, inheritable bool) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("DACL for %q is not protected", path)
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]windows.ACCESS_MASK)
	for i := uint16(0); i < acl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, uint32(i), &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatalf("ACE %d for %q has type %d", i, path, ace.Header.AceType)
		}
		if inheritable && ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE {
			t.Fatalf("ACE %d for %q is not inheritable", i, path)
		}
		if !inheritable && ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != 0 {
			t.Fatalf("ACE %d for %q is unexpectedly inheritable", i, path)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		got[sid.String()] = ace.Mask
	}
	if len(got) != len(want) {
		t.Fatalf("DACL for %q has %d principals, want %d: %v", path, len(got), len(want), got)
	}
	for sid, access := range want {
		if got[sid] != access {
			t.Fatalf("DACL access for %s on %q = %#x, want %#x", sid, path, got[sid], access)
		}
	}
}
