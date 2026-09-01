package connectorhost

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLocalControlAuthenticatesAndCleansMatchingDescriptor(t *testing.T) {
	root := filepath.Join(t.TempDir(), "instance")
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host := newTestHost(store, nil)
	server, err := NewLocalControlServer(host, 0)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := ReadControlDescriptor(root)
	if err != nil {
		t.Fatal(err)
	}
	token, err := base64.RawURLEncoding.DecodeString(descriptor.Token)
	if err != nil || len(token) != 32 || descriptor.Port == 0 || descriptor.PID != os.Getpid() {
		t.Fatalf("descriptor = %+v, token bytes = %d, error = %v", descriptor, len(token), err)
	}
	info, err := os.Stat(filepath.Join(root, controlDescriptor))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("descriptor mode = %o", info.Mode().Perm())
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx) }()
	request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+portString(descriptor.Port)+"/v1/access", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", response.StatusCode)
	}
	client, err := NewLocalControlClient(root)
	if err != nil {
		t.Fatal(err)
	}
	if transport := client.http.Transport.(*http.Transport); transport.Proxy != nil {
		t.Fatal("local control client has a proxy function")
	}
	if err := client.SetAccess(t.Context(), AccessNone); err != nil {
		t.Fatal(err)
	}
	if mode, err := client.Access(t.Context()); err != nil || mode != AccessNone {
		t.Fatalf("access = %q, %v", mode, err)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, controlDescriptor)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("descriptor remains after shutdown: %v", err)
	}
}

func TestLocalControlPreservesDescriptorWithDifferentNonce(t *testing.T) {
	root := filepath.Join(t.TempDir(), "instance")
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server, err := NewLocalControlServer(newTestHost(store, nil), 0)
	if err != nil {
		t.Fatal(err)
	}
	replacement := server.descriptor
	replacement.Nonce, err = randomControlSecret(24)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(replacement)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(root, controlDescriptor), body, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx) }()
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	current, err := ReadControlDescriptor(root)
	if err != nil || current.Nonce != replacement.Nonce {
		t.Fatalf("replacement descriptor = %+v, %v", current, err)
	}
}

func TestLocalControlRejectsUnknownJSONFields(t *testing.T) {
	root := filepath.Join(t.TempDir(), "instance")
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server, err := NewLocalControlServer(newTestHost(store, nil), 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx) }()
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+portString(server.descriptor.Port)+"/v1/access", bytes.NewBufferString(`{"mode":"full","extra":true}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+server.descriptor.Token)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown-field status = %d", response.StatusCode)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func portString(port int) string {
	return fmt.Sprint(port)
}
