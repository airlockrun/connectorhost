package connectorhost

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

func TestStoreDefaultsFullPersistsAndLocks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "instance")
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if store.AccessMode() != AccessFull {
		t.Fatalf("default access = %q", store.AccessMode())
	}
	if _, err := OpenStore(root); !errors.Is(err, ErrStateLocked) {
		t.Fatalf("second store lock error = %v", err)
	}
	if err := store.SetAccessMode(AccessUpdateOnly); err != nil {
		t.Fatal(err)
	}
	if err := store.SetCredentials("https://airlock.example", "secret", "host-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if store.AccessMode() != AccessUpdateOnly || store.HostID() != "host-1" {
		t.Fatalf("reloaded state = %q / %q", store.AccessMode(), store.HostID())
	}
	info, err := os.Stat(filepath.Join(root, "host.json"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("state mode = %o", info.Mode().Perm())
	}
}

func TestStorePersistsManagementOutcomesUntilAcknowledged(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "instance"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	outcome := managementOutcome{JobID: "job-1", AttemptToken: "attempt-1", Kind: protocol.HostWorkShell, Status: "success", Output: json.RawMessage(`{"exitCode":0}`)}
	if err := store.saveManagementOutcome(outcome); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := store.loadManagementOutcome(outcome.JobID)
	var output struct {
		ExitCode int `json:"exitCode"`
	}
	decodeErr := json.Unmarshal(loaded.Output, &output)
	if err != nil || !found || loaded.Status != "success" || decodeErr != nil || output.ExitCode != 0 {
		t.Fatalf("loadManagementOutcome() = %+v, %t, %v", loaded, found, err)
	}
	if err := store.removeManagementOutcome(outcome.JobID); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.loadManagementOutcome(outcome.JobID); err != nil || found {
		t.Fatalf("removed outcome found = %t, error = %v", found, err)
	}
}

func TestStoreRejectsTraversalInstallationID(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "instance"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.RemoveConnector("../outside"); err == nil {
		t.Fatal("traversal installation ID accepted")
	}
}
