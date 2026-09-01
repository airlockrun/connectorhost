package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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
	host := connectorhost.NewHost(store, nil)
	server, err := connectorhost.NewLocalControlServer(host, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx) }()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--state-dir", root, "access", "set", "none"}, &stdout, &stderr); err != nil {
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

func TestAccessCommandFallsBackToDirectStore(t *testing.T) {
	root := filepath.Join(t.TempDir(), "instance")
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--state-dir", root, "access", "set", "update_only"}, &stdout, &stderr); err != nil {
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
