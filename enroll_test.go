package connectorhost

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnenrolledHostStaysAvailableAndEnrollsThroughLocalControl(t *testing.T) {
	var airlock *httptest.Server
	synced := make(chan struct{}, 1)
	airlock = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/hosts/v1/enroll/device-code":
			_ = json.NewEncoder(w).Encode(hostDeviceCodeResponse{
				DeviceSecret:        "device-secret",
				UserCode:            "ABCD-EFGH",
				VerificationURL:     airlock.URL + "/verify",
				ExpiresAt:           time.Now().Add(time.Minute),
				PollIntervalSeconds: 1,
			})
		case "/api/hosts/v1/enroll/complete":
			_ = json.NewEncoder(w).Encode(hostEnrollmentResponse{Status: "approved", HostID: "host-1", Credential: "credential-1"})
		default:
			select {
			case synced <- struct{}{}:
			default:
			}
			http.Error(w, `{"error":"retry"}`, http.StatusServiceUnavailable)
		}
	}))
	defer airlock.Close()

	root := filepath.Join(t.TempDir(), "instance")
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	host := newTestHost(store, airlock.Client())
	ctx, cancel := context.WithCancel(context.Background())
	serveResult := make(chan error, 1)
	go func() { serveResult <- host.ServeControl(ctx, 0) }()
	t.Cleanup(func() {
		cancel()
		<-serveResult
		_ = store.Close()
	})

	client := waitForLocalControlClient(t, root)
	time.Sleep(100 * time.Millisecond)
	if _, err := client.Access(t.Context()); err != nil {
		t.Fatalf("unenrolled host local control is unavailable: %v", err)
	}

	var prompt EnrollmentPrompt
	if err := client.Enroll(t.Context(), airlock.URL, AccessUpdateOnly, func(value EnrollmentPrompt) error {
		prompt = value
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if prompt.VerificationURL != airlock.URL+"/verify" || prompt.UserCode != "ABCD-EFGH" {
		t.Fatalf("prompt = %+v", prompt)
	}
	baseURL, credential := store.Credentials()
	if baseURL != airlock.URL || credential != "credential-1" || store.HostID() != "host-1" {
		t.Fatalf("credentials = %q / %q / %q", baseURL, credential, store.HostID())
	}
	if store.AccessMode() != AccessUpdateOnly {
		t.Fatalf("access mode = %q", store.AccessMode())
	}
	if err := client.Enroll(t.Context(), airlock.URL, AccessNone, func(EnrollmentPrompt) error { return nil }); err == nil {
		t.Fatal("already-enrolled host accepted another enrollment")
	}
	if store.AccessMode() != AccessUpdateOnly {
		t.Fatalf("failed enrollment changed access mode to %q", store.AccessMode())
	}
	select {
	case <-synced:
	case <-time.After(5 * time.Second):
		t.Fatal("remote loop did not start after local enrollment")
	}
}

func TestFailedEnrollmentPreservesAccessMode(t *testing.T) {
	var requestedMode AccessMode
	var airlock *httptest.Server
	airlock = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/hosts/v1/enroll/device-code":
			var info struct {
				AccessMode AccessMode `json:"accessMode"`
			}
			if err := json.NewDecoder(request.Body).Decode(&info); err != nil {
				t.Error(err)
			}
			requestedMode = info.AccessMode
			_ = json.NewEncoder(w).Encode(hostDeviceCodeResponse{
				DeviceSecret:        "device-secret",
				UserCode:            "ABCD-EFGH",
				VerificationURL:     airlock.URL + "/verify",
				ExpiresAt:           time.Now().Add(time.Minute),
				PollIntervalSeconds: 1,
			})
		case "/api/hosts/v1/enroll/complete":
			_ = json.NewEncoder(w).Encode(hostEnrollmentResponse{Status: "denied"})
		default:
			http.NotFound(w, request)
		}
	}))
	defer airlock.Close()

	store, err := OpenStore(filepath.Join(t.TempDir(), "instance"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.SetAccessMode(AccessUpdateOnly); err != nil {
		t.Fatal(err)
	}
	err = EnrollWithPrompt(t.Context(), store, airlock.URL, AccessNone, airlock.Client(), func(EnrollmentPrompt) error { return nil })
	if err == nil {
		t.Fatal("denied enrollment returned success")
	}
	if requestedMode != AccessNone {
		t.Fatalf("requested mode = %q", requestedMode)
	}
	if store.AccessMode() != AccessUpdateOnly {
		t.Fatalf("failed enrollment changed access mode to %q", store.AccessMode())
	}
}

func waitForLocalControlClient(t *testing.T, root string) *LocalControlClient {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		client, err := NewLocalControlClient(root)
		if err == nil {
			return client
		}
		if !os.IsNotExist(err) || time.Now().After(deadline) {
			t.Fatalf("wait for local control: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
