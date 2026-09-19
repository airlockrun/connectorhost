package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	connectorhost "github.com/airlockrun/connectorhost"
)

func TestAccessCommandUsesControlServerWhenStoreIsLocked(t *testing.T) {
	root := filepath.Join(t.TempDir(), "instance")
	store, err := connectorhost.OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host := connectorhost.NewHost(store, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server, err := connectorhost.NewLocalControlServer(host, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx) }()
	var stdout, stderr bytes.Buffer
	for _, mode := range []connectorhost.AccessMode{connectorhost.AccessFull, connectorhost.AccessManage, connectorhost.AccessUpdates, connectorhost.AccessNone} {
		t.Run(string(mode), func(t *testing.T) {
			if err := run([]string{"--state-dir", root, "access", "set", string(mode)}, bytes.NewReader(nil), &stdout, &stderr); err != nil {
				t.Fatal(err)
			}
			if store.AccessMode() != mode {
				t.Fatalf("access mode = %q", store.AccessMode())
			}
		})
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestManagedCommandsUseManagedServiceState(t *testing.T) {
	managed := func() (string, error) { return "/managed", nil }
	standalone := func() (string, error) { return "/standalone", nil }
	for _, command := range []string{"access", "connector"} {
		root, err := resolveStateDirectory(command, managed, standalone)
		if err != nil {
			t.Fatal(err)
		}
		if root != "/managed" {
			t.Fatalf("%s state directory = %q", command, root)
		}
	}
	root, err := resolveStateDirectory("serve", managed, standalone)
	if err != nil {
		t.Fatal(err)
	}
	if root != "/standalone" {
		t.Fatalf("serve state directory = %q", root)
	}
}

func TestAccessCommandFallsBackToDirectStore(t *testing.T) {
	root := filepath.Join(t.TempDir(), "instance")
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--state-dir", root, "access", "set", "manage"}, bytes.NewReader(nil), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	store, err := connectorhost.OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if store.AccessMode() != connectorhost.AccessManage {
		t.Fatalf("access mode = %q", store.AccessMode())
	}
}

func TestStandaloneUnenrollRequiresConfirmationAndDeletesState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "instance")
	store, err := connectorhost.OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetCredentials("https://airlock.example", "credential", "host-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--state-dir", root, "unenroll"}, bytes.NewReader(nil), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "--delete-connectors") {
		t.Fatalf("missing confirmation error = %v", err)
	}
	var output bytes.Buffer
	if err := run([]string{"--state-dir", root, "unenroll", "--delete-connectors"}, bytes.NewReader(nil), &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "unenrolled") {
		t.Fatalf("output = %q", output.String())
	}
	store, err = connectorhost.OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	airlockURL, credential := store.Credentials()
	if airlockURL != "" || credential != "" || store.HostID() != "" {
		t.Fatal("unenroll retained enrollment")
	}
}

func TestStandaloneUnenrollRejectsRunningHost(t *testing.T) {
	root := filepath.Join(t.TempDir(), "instance")
	store, err := connectorhost.OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	err = run([]string{"--state-dir", root, "unenroll", "--delete-connectors"}, bytes.NewReader(nil), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "stop its serve process") {
		t.Fatalf("unenroll error = %v", err)
	}
}

func TestMutatingControlLostResponseIsNotReplayed(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		remote func(context.Context, *connectorhost.LocalControlClient) error
	}{
		{name: "update", path: "/v1/connectors/update", remote: func(ctx context.Context, client *connectorhost.LocalControlClient) error {
			return client.Update(ctx, connectorhost.LocalUpdateRequest{InstallationID: "connector-1", SourcePath: "/connector"})
		}},
		{name: "rollback", path: "/v1/connectors/rollback", remote: func(ctx context.Context, client *connectorhost.LocalControlClient) error {
			return client.Rollback(ctx, "connector-1")
		}},
		{name: "remove", path: "/v1/connectors/remove", remote: func(ctx context.Context, client *connectorhost.LocalControlClient) error {
			return client.Remove(ctx, "connector-1")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "instance")
			store, err := connectorhost.OpenStore(root)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path != test.path {
					t.Errorf("request path = %q", request.URL.Path)
				}
				_, _ = io.Copy(io.Discard, request.Body)
				requests.Add(1)
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("hijack response: %v", err)
					return
				}
				_ = connection.Close()
			}))
			defer server.Close()
			parsed, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(parsed.Port())
			if err != nil {
				t.Fatal(err)
			}
			descriptor := connectorhost.ControlDescriptor{
				Protocol: 1,
				Port:     port,
				Token:    base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
				PID:      os.Getpid(),
				Nonce:    base64.RawURLEncoding.EncodeToString(make([]byte, 24)),
			}
			body, err := json.Marshal(descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "control.json"), body, 0o600); err != nil {
				t.Fatal(err)
			}
			var directCalls atomic.Int32
			err = controlFirst(root, false, test.remote, func(context.Context, *connectorhost.Host, *connectorhost.Store) error {
				directCalls.Add(1)
				return nil
			})
			if err == nil {
				t.Fatal("lost response returned success")
			}
			if requests.Load() != 1 || directCalls.Load() != 0 {
				t.Fatalf("requests = %d, direct calls = %d", requests.Load(), directCalls.Load())
			}
		})
	}
}

func TestEnrollmentModeFlagAndPrompt(t *testing.T) {
	for _, test := range []struct {
		number string
		mode   connectorhost.AccessMode
	}{
		{"1", connectorhost.AccessFull},
		{"2", connectorhost.AccessManage},
		{"3", connectorhost.AccessUpdates},
		{"4", connectorhost.AccessNone},
	} {
		t.Run(string(test.mode), func(t *testing.T) {
			mode, err := selectEnrollmentMode(string(test.mode), bytes.NewReader(nil), io.Discard, false)
			if err != nil || mode != test.mode {
				t.Fatalf("flag mode = %q, %v", mode, err)
			}
			for _, input := range []string{test.number, string(test.mode)} {
				mode, err := selectEnrollmentMode("", strings.NewReader(input+"\n"), io.Discard, true)
				if err != nil || mode != test.mode {
					t.Fatalf("prompt %q = %q, %v", input, mode, err)
				}
			}
		})
	}

	var output bytes.Buffer
	mode, err := selectEnrollmentMode("", bytes.NewBufferString("invalid\n4\n"), &output, true)
	if err != nil || mode != connectorhost.AccessNone {
		t.Fatalf("prompt mode = %q, %v", mode, err)
	}
	for _, text := range []string{"1) full", "2) Manage", "3) Updates", "4) none", "no shell", "connector jobs still run", "Enter 1, 2, 3, 4", "Mode [1/2/3/4]"} {
		if !strings.Contains(output.String(), text) {
			t.Fatalf("prompt lacks %q: %q", text, output.String())
		}
	}
	for _, value := range []string{"manage_connectors", "update_only", "manage-connectors", "Manage", "Updates", " manage "} {
		t.Run("invalid/"+value, func(t *testing.T) {
			if _, err := selectEnrollmentMode(value, bytes.NewReader(nil), io.Discard, false); err == nil {
				t.Fatal("invalid flag accepted")
			}
			if err := accessCommand(t.TempDir(), []string{"set", value}, io.Discard); err == nil {
				t.Fatal("invalid access command accepted")
			}
		})
	}
	if _, err := selectEnrollmentMode("", bytes.NewReader(nil), io.Discard, true); err == nil {
		t.Fatal("EOF selected a mode")
	}
}

func TestEnrollmentModeRequiredWithoutTerminal(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"enroll", "--airlock", "https://airlock.example"}, bytes.NewReader(nil), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "requires --mode") {
		t.Fatalf("run error = %v", err)
	}
}

func TestRootHelpShowsManagedQuickStart(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(nil, bytes.NewReader(nil), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Managed host quick start") || !strings.Contains(stdout.String(), "--user service install") || !strings.Contains(stdout.String(), "--mode") {
		t.Fatalf("help output = %q", stdout.String())
	}
}

func TestUserServiceRejectsStandaloneState(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"--user", "--state-dir", t.TempDir(), "access", "get"}, bytes.NewReader(nil), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("run error = %v", err)
	}
}

func TestUserServiceRejectsStandaloneServe(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"--user", "serve"}, bytes.NewReader(nil), &stdout, &stderr)
	want := "cannot be used with serve"
	if !nativeServiceSupported {
		want = "per-user managed services are supported on Linux"
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("run error = %v", err)
	}
}

func TestUserFlagRoutesManagedCommandsToUserService(t *testing.T) {
	root := filepath.Join(t.TempDir(), "user-state")
	var scopes []nativeServiceScope
	factory := func(scope nativeServiceScope) (nativeServiceManager, error) {
		scopes = append(scopes, scope)
		return &testNativeServiceManager{stateDirectory: root, status: nativeServiceStatus{State: serviceNotInstalled}}, nil
	}
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{"connector", []string{"--user", "connector", "list"}, ""},
		{"status", []string{"--user", "service", "status"}, ""},
		{"enroll", []string{"--user", "enroll", "--airlock", "https://airlock.example", "--mode", "none"}, "--user service install"},
		{"service enroll", []string{"--user", "service", "enroll", "--airlock", "https://airlock.example", "--mode", "none"}, "--user service install"},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := test.want
			if !nativeServiceSupported {
				want = "per-user managed services are supported on Linux"
			}
			var stdout, stderr bytes.Buffer
			err := runWithServiceManager(test.args, bytes.NewReader(nil), &stdout, &stderr, factory)
			if want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("run(%v) error = %v, want %q", test.args, err, want)
			}
		})
	}
	want := []nativeServiceScope{nativeServiceUser, nativeServiceUser, nativeServiceUser, nativeServiceUser}
	if !nativeServiceSupported {
		want = nil
	}
	if !reflect.DeepEqual(scopes, want) {
		t.Fatalf("manager scopes = %v, want %v", scopes, want)
	}
}

func TestEnrollmentHelpReturnsSuccess(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"enroll", "--help"}, bytes.NewReader(nil), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "-mode") {
		t.Fatalf("help output = %q", stderr.String())
	}
}
