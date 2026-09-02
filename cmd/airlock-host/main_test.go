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
	if err := run([]string{"--state-dir", root, "access", "set", "none"}, bytes.NewReader(nil), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if store.AccessMode() != connectorhost.AccessNone {
		t.Fatalf("access mode = %q", store.AccessMode())
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
	if err := run([]string{"--state-dir", root, "access", "set", "update_only"}, bytes.NewReader(nil), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	store, err := connectorhost.OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if store.AccessMode() != connectorhost.AccessUpdateOnly {
		t.Fatalf("access mode = %q", store.AccessMode())
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
	mode, err := selectEnrollmentMode("update_only", bytes.NewReader(nil), io.Discard, false)
	if err != nil || mode != connectorhost.AccessUpdateOnly {
		t.Fatalf("flag mode = %q, %v", mode, err)
	}

	var output bytes.Buffer
	mode, err = selectEnrollmentMode("", bytes.NewBufferString("invalid\n3\n"), &output, true)
	if err != nil || mode != connectorhost.AccessNone {
		t.Fatalf("prompt mode = %q, %v", mode, err)
	}
	if !strings.Contains(output.String(), "connector jobs still run") || !strings.Contains(output.String(), "Enter 1, 2, 3") {
		t.Fatalf("prompt output = %q", output.String())
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
	if err == nil || !strings.Contains(err.Error(), "cannot be used with serve") {
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
	var stdout, stderr bytes.Buffer
	if err := runWithServiceManager([]string{"--user", "connector", "list"}, bytes.NewReader(nil), &stdout, &stderr, factory); err != nil {
		t.Fatal(err)
	}
	if err := runWithServiceManager([]string{"--user", "service", "status"}, bytes.NewReader(nil), &stdout, &stderr, factory); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--user", "enroll", "--airlock", "https://airlock.example", "--mode", "none"},
		{"--user", "service", "enroll", "--airlock", "https://airlock.example", "--mode", "none"},
	} {
		err := runWithServiceManager(args, bytes.NewReader(nil), &stdout, &stderr, factory)
		if err == nil || !strings.Contains(err.Error(), "--user service install") {
			t.Fatalf("run(%v) error = %v", args, err)
		}
	}
	want := []nativeServiceScope{nativeServiceUser, nativeServiceUser, nativeServiceUser, nativeServiceUser}
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
