package connectorhost

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

func TestRemoteArtifactRejectsInvalidStorageOriginsBeforeDownload(t *testing.T) {
	tests := []struct {
		name    string
		origins []string
	}{
		{name: "malformed", origins: []string{"://storage.example"}},
		{name: "duplicate", origins: []string{"https://storage.example", "https://storage.example"}},
		{name: "non-HTTPS", origins: []string{"http://storage.example"}},
		{name: "oversized origin", origins: []string{"https://" + strings.Repeat("a", protocol.MaxHostStorageOriginBytes) + ".example"}},
		{name: "too many origins", origins: make([]string, protocol.MaxHostStorageOrigins+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				requests.Add(1)
			}))
			defer server.Close()
			store, err := OpenStore(filepath.Join(t.TempDir(), "instance"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			input := protocol.ConnectorArtifactInput{
				InstallationID: inventoryID,
				URL:            server.URL + "/connector",
				Filename:       "connector",
				SHA256:         strings.Repeat("a", 64),
				SizeBytes:      1,
				StorageOrigins: test.origins,
			}
			if _, err := NewArtifactInstaller(store, server.Client()).Stage(t.Context(), input, nil); err == nil {
				t.Fatal("invalid storage origins accepted")
			}
			if requests.Load() != 0 {
				t.Fatalf("artifact was downloaded %d times", requests.Load())
			}
			if _, err := os.Stat(filepath.Join(store.root, "connectors", inventoryID)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("artifact staging directory exists: %v", err)
			}
		})
	}
}

func TestManifestInspectionTerminatesInheritedPipeDescendant(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pidPath := filepath.Join(t.TempDir(), "manifest-descendant.pid")
	t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_MANIFEST_DESCENDANT_PATH", pidPath)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	if _, err := inspectManifest(ctx, executable); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("manifest inspection waited on inherited pipe for %s", elapsed)
	}
	waitForStoppedTestProcess(t, waitForTestPID(t, pidPath))
}

func TestManifestInspectionTimeoutTerminatesProcessTree(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pidPath := filepath.Join(t.TempDir(), "manifest-descendant.pid")
	t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_MANIFEST_DESCENDANT_PATH", pidPath)
	t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_MANIFEST_HANG", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	started := time.Now()
	_, err = inspectManifest(ctx, executable)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("manifest timeout error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("manifest timeout returned after %s", elapsed)
	}
	waitForStoppedTestProcess(t, waitForTestPID(t, pidPath))
}

func TestManifestInspectionBoundsOutput(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_MANIFEST_OVERFLOW", "1")
	if _, err := inspectManifest(t.Context(), executable); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized manifest error = %v", err)
	}
}

func waitForStoppedTestProcess(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for processRunning(pid) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if processRunning(pid) {
		t.Fatalf("contained descendant %d remains running", pid)
	}
}
