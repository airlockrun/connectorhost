package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type linuxCommandCall struct {
	name string
	args []string
}

type linuxTestExitError int

func (err linuxTestExitError) Error() string {
	return "exit status"
}

func (err linuxTestExitError) ExitCode() int {
	return int(err)
}

func TestLinuxSystemdUnit(t *testing.T) {
	manager := &linuxServiceManager{paths: linuxServicePaths{
		executable:     "/usr/local/bin/airlock-host",
		stateDirectory: "/var/lib/airlock-host",
	}}
	want := `[Unit]
Description=Airlock Connector Host
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=airlock-host
Group=airlock-host
ExecStart="/usr/local/bin/airlock-host" "--state-dir" "/var/lib/airlock-host" "serve" "--control-port" "42927"
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
`
	if got := manager.systemdUnit(); got != want {
		t.Fatalf("systemd unit:\n%s\nwant:\n%s", got, want)
	}

	manager.paths.executable = `/opt/Airlock Host/$channel%/airlock"host`
	manager.paths.stateDirectory = "/var/lib/Airlock Host"
	line := `ExecStart="/opt/Airlock Host/$$channel%%/airlock\"host" "--state-dir" "/var/lib/Airlock Host" "serve" "--control-port" "42927"`
	if !strings.Contains(manager.systemdUnit(), line+"\n") {
		t.Fatalf("systemd unit does not safely quote ExecStart:\n%s", manager.systemdUnit())
	}
}

func TestLinuxInstallIsIdempotent(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "current-airlock-host")
	if err := os.WriteFile(sourcePath, []byte("executable bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	var calls []linuxCommandCall
	userExists := false
	expectedStateDirectory := filepath.Join(root, "var lib", "airlock-host")
	manager := newTestLinuxServiceManager(root, sourcePath, func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, linuxCommandCall{name: name, args: append([]string(nil), args...)})
		if name == "id" && !userExists {
			return nil, linuxTestExitError(1)
		}
		if name == "useradd" {
			userExists = true
		}
		if name == "id" && len(args) > 0 && args[0] == "--group" {
			return []byte("airlock-host\n"), nil
		}
		if name == "id" && len(args) > 0 && args[0] == "--user" {
			return []byte("999\n"), nil
		}
		if name == "getent" {
			return []byte("airlock-host:x:999:999::" + expectedStateDirectory + ":/usr/sbin/nologin\n"), nil
		}
		if name == "passwd" {
			return []byte("airlock-host L 2026-09-01 0 99999 7 -1\n"), nil
		}
		return nil, nil
	})
	if err := os.WriteFile(manager.passwdFile, []byte("airlock-host:x:999:999::"+expectedStateDirectory+":/usr/sbin/nologin\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := manager.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantCalls := []linuxCommandCall{
		{name: "groupadd", args: []string{"--system", "--force", "airlock-host"}},
		{name: "id", args: []string{"--user", "airlock-host"}},
		{name: "useradd", args: []string{"--system", "--gid", "airlock-host", "--home-dir", manager.paths.stateDirectory, "--shell", "/usr/sbin/nologin", "--no-create-home", "airlock-host"}},
		{name: "id", args: []string{"--user", "airlock-host"}},
		{name: "id", args: []string{"--group", "--name", "airlock-host"}},
		{name: "getent", args: []string{"passwd", "airlock-host"}},
		{name: "passwd", args: []string{"--status", "airlock-host"}},
		{name: "chown", args: []string{"--recursive", "--no-dereference", "airlock-host:airlock-host", manager.paths.stateDirectory}},
		{name: "systemctl", args: []string{"enable", "airlock-host.service"}},
		{name: "systemctl", args: []string{"daemon-reload"}},
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("commands = %#v, want %#v", calls, wantCalls)
	}
	installed, err := os.ReadFile(manager.paths.executable)
	if err != nil {
		t.Fatal(err)
	}
	if string(installed) != "executable bytes" {
		t.Fatalf("installed executable = %q", installed)
	}
	executableInfo, err := os.Stat(manager.paths.executable)
	if err != nil {
		t.Fatal(err)
	}
	if executableInfo.Mode().Perm() != 0o755 {
		t.Fatalf("installed executable mode = %o", executableInfo.Mode().Perm())
	}
	stateInfo, err := os.Stat(manager.paths.stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if stateInfo.Mode().Perm() != 0o750 {
		t.Fatalf("state directory mode = %o", stateInfo.Mode().Perm())
	}
	unit, err := os.ReadFile(manager.paths.unitFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(unit) != manager.systemdUnit() {
		t.Fatalf("installed unit:\n%s\nwant:\n%s", unit, manager.systemdUnit())
	}

	calls = nil
	if err := manager.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(manager.paths.executable)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(executableInfo, afterInfo) {
		t.Fatal("unchanged executable was replaced")
	}
	for _, call := range calls {
		if call.name == "useradd" || call.name == "systemctl" && len(call.args) > 0 && call.args[0] == "start" {
			t.Fatalf("unexpected command on repeated install: %#v", call)
		}
	}
}

func TestLinuxInstallToleratesOfflineSystemdManager(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "airlock-host")
	if err := os.WriteFile(sourcePath, []byte("executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	manager := newTestLinuxServiceManager(root, sourcePath, func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "id" && len(args) > 0 && args[0] == "--group" {
			return []byte("airlock-host\n"), nil
		}
		if name == "id" && len(args) > 0 && args[0] == "--user" {
			return []byte("999\n"), nil
		}
		if name == "getent" {
			return []byte("airlock-host:x:999:999::" + managerStateDirectory(root) + ":/usr/sbin/nologin\n"), nil
		}
		if name == "passwd" {
			return []byte("airlock-host L 2026-09-01 0 99999 7 -1\n"), nil
		}
		if name == "systemctl" && len(args) > 0 && args[0] == "daemon-reload" {
			return []byte("System has not been booted with systemd as init system (PID 1). Can't operate.\nFailed to connect to bus: Host is down\n"), linuxTestExitError(1)
		}
		return nil, nil
	})
	manager.passwdFile = filepath.Join(root, "passwd")
	if err := os.WriteFile(manager.passwdFile, []byte("airlock-host:x:999:999::"+manager.paths.stateDirectory+":/usr/sbin/nologin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := manager.Install(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxInstallRequiresRootBeforeInspectingExecutable(t *testing.T) {
	called := false
	manager := &linuxServiceManager{
		effectiveUID: func() int { return 1000 },
		currentExe: func() (string, error) {
			called = true
			return "", errors.New("unexpected")
		},
	}
	if err := manager.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "requires root") {
		t.Fatalf("Install error = %v", err)
	}
	if called {
		t.Fatal("current executable inspected before root validation")
	}
}

func TestLinuxLifecycleCommandsAndUninstallPreservesData(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "source")
	manager := newTestLinuxServiceManager(root, sourcePath, nil)
	if err := os.MkdirAll(filepath.Dir(manager.paths.unitFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manager.paths.unitFile, []byte("unit"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(manager.paths.stateDirectory, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manager.paths.stateDirectory, "state"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(manager.paths.executable), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manager.paths.executable, []byte("keep"), 0o755); err != nil {
		t.Fatal(err)
	}

	activeState := "active"
	var calls []linuxCommandCall
	manager.runCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, linuxCommandCall{name: name, args: append([]string(nil), args...)})
		if name == "systemctl" && len(args) > 0 && args[0] == "show" {
			pid := "123"
			if activeState != "active" {
				pid = "0"
			}
			return []byte("LoadState=loaded\nActiveState=" + activeState + "\nSubState=running\nFreezerState=running\nMainPID=" + pid + "\n"), nil
		}
		if name == "systemctl" && len(args) > 0 && args[0] == "stop" {
			activeState = "inactive"
		}
		return nil, nil
	}

	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(manager.paths.unitFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unit file still exists: %v", err)
	}
	if body, err := os.ReadFile(manager.paths.executable); err != nil || string(body) != "keep" {
		t.Fatalf("executable changed: body %q, error %v", body, err)
	}
	if body, err := os.ReadFile(filepath.Join(manager.paths.stateDirectory, "state")); err != nil || string(body) != "keep" {
		t.Fatalf("state changed: body %q, error %v", body, err)
	}
	if err := manager.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}

	wantActions := []string{"show", "show", "stop", "show", "show", "disable", "daemon-reload", "daemon-reload"}
	var actions []string
	for _, call := range calls {
		if call.name == "systemctl" {
			actions = append(actions, call.args[0])
		}
	}
	if !reflect.DeepEqual(actions, wantActions) {
		t.Fatalf("systemctl actions = %v, want %v", actions, wantActions)
	}
}

func TestLinuxCommandsAreBounded(t *testing.T) {
	root := t.TempDir()
	manager := newTestLinuxServiceManager(root, filepath.Join(root, "source"), func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	manager.commandTimeout = 20 * time.Millisecond
	if err := os.MkdirAll(filepath.Dir(manager.paths.unitFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manager.paths.unitFile, []byte("unit"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := manager.Status(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Status error = %v", err)
	}
}

func newTestLinuxServiceManager(root, sourcePath string, runner linuxCommandRunner) *linuxServiceManager {
	if runner == nil {
		runner = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	}
	return &linuxServiceManager{
		paths: linuxServicePaths{
			executable:     filepath.Join(root, "usr local", "bin", "airlock-host"),
			stateDirectory: filepath.Join(root, "var lib", "airlock-host"),
			unitFile:       filepath.Join(root, "etc", "systemd", "system", linuxServiceUnitName),
		},
		currentExe:     func() (string, error) { return sourcePath, nil },
		effectiveUID:   func() int { return 0 },
		runCommand:     runner,
		ready:          func(context.Context, string) error { return nil },
		passwdFile:     filepath.Join(root, "passwd"),
		commandTimeout: time.Second,
	}
}

func managerStateDirectory(root string) string {
	return filepath.Join(root, "var lib", "airlock-host")
}
