package connectorhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalInstallBypassesRemoteAccessAndUpdatePreservesSettings(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "instance")
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.SetAccessMode(AccessNone); err != nil {
		t.Fatal(err)
	}
	host := newTestHost(store, nil)
	t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_CHILD", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	response, err := host.LocalInstall(ctx, LocalInstallRequest{SourcePath: executable, DisplayName: "Local helper", Settings: json.RawMessage(`{"value":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.InstallLocal(ctx, LocalArtifactInput{InstallationID: response.InstallationID, SourcePath: executable}, true); err != nil {
		t.Fatal(err)
	}
	record, exists := store.Connector(response.InstallationID)
	if !exists || string(record.Settings) != `{"value":1}` || record.DisplayName != "Local helper" || record.PreviousDigest == "" {
		t.Fatalf("updated record = %+v, exists = %t", record, exists)
	}
	if err := host.Rollback(ctx, response.InstallationID); err != nil {
		t.Fatal(err)
	}
	if err := host.Remove(ctx, response.InstallationID); err != nil {
		t.Fatal(err)
	}
	if _, exists := store.Connector(response.InstallationID); exists {
		t.Fatal("removed connector remains in state")
	}
	stopCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := host.Close(stopCtx); err != nil {
		t.Fatal(err)
	}
}

func TestLocalInstallRejectsDigestMismatch(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(filepath.Join(t.TempDir(), "instance"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host := newTestHost(store, nil)
	_, err = host.LocalInstall(t.Context(), LocalInstallRequest{InstallationID: "mismatch-id", SourcePath: executable, ExpectedSHA256: strings.Repeat("0", 64)})
	if err == nil || len(store.Connectors()) != 0 {
		t.Fatalf("digest mismatch error = %v, connectors = %d", err, len(store.Connectors()))
	}
	if _, statErr := os.Stat(filepath.Join(store.root, "connectors", "mismatch-id")); !os.IsNotExist(statErr) {
		t.Fatalf("failed staging directory remains: %v", statErr)
	}
}

func TestCandidateReadinessPrecedesPersistence(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	store, err := OpenStore(filepath.Join(t.TempDir(), "instance"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host := newTestHost(store, nil)
	t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_CHILD", "1")
	t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_READINESS", "fail")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = host.LocalInstall(ctx, LocalInstallRequest{SourcePath: executable, ExpectedSHA256: hex.EncodeToString(digest[:])})
	if err == nil {
		t.Fatal("unhealthy candidate installed")
	}
	if connectors := store.Connectors(); len(connectors) != 0 {
		t.Fatalf("candidate persisted before readiness: %+v", connectors)
	}
}

func TestInvalidLocalInstallIDDoesNotRemoveConnectorDirectory(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "instance"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	marker := filepath.Join(store.root, "connectors", "keep", "marker")
	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = newTestHost(store, nil).InstallLocal(t.Context(), LocalArtifactInput{InstallationID: "", SourcePath: "/missing"}, false)
	if err == nil {
		t.Fatal("empty installation ID accepted")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("invalid install removed connector directory: %v", err)
	}
}
