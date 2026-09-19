package connectorhost

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

func TestResetStateDeletesHostIdentityAndConnectorData(t *testing.T) {
	root := t.TempDir()
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetCredentials("https://airlock.example", "credential", "host-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.PutConnector(inventoryTestRecord(inventoryID)); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(root, "connectors", inventoryID, "state", "data"),
		filepath.Join(root, "outbox", "event.json"),
		filepath.Join(root, "management", "job.json"),
		filepath.Join(root, "logs", "host.log"),
		filepath.Join(root, ".upload-stale", "part"),
		filepath.Join(root, "control.json"),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("old host data"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ResetState(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "host.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reset caller recreated host.json: %v", err)
	}
	store, err = OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	airlockURL, credential := store.Credentials()
	if airlockURL != "" || credential != "" || store.HostID() != "" {
		t.Fatalf("enrollment remains: url=%q credential=%q host=%q", airlockURL, credential, store.HostID())
	}
	if len(store.Connectors()) != 0 || len(store.PendingInventoryMutations()) != 0 {
		t.Fatal("connector inventory remains after reset")
	}
	if store.AccessMode() != AccessFull {
		t.Fatalf("access mode = %q, want %q", store.AccessMode(), AccessFull)
	}
	for _, name := range []string{"connectors", "outbox", "management", "logs", ".upload-stale", "control.json", resetMarkerName} {
		if _, err := os.Lstat(filepath.Join(root, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s remains after reset: %v", name, err)
		}
	}
}

func TestResetStateRejectsUnsafeRoots(t *testing.T) {
	for _, test := range []struct {
		name string
		root func(*testing.T) string
	}{
		{name: "missing", root: func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") }},
		{name: "unrelated", root: func(t *testing.T) string {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "important"), []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			return root
		}},
		{name: "filesystem root", root: func(*testing.T) string { return filepath.VolumeName(t.TempDir()) + string(os.PathSeparator) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := test.root(t)
			if err := ResetState(root); err == nil {
				t.Fatal("unsafe reset succeeded")
			}
			if test.name == "unrelated" {
				body, err := os.ReadFile(filepath.Join(root, "important"))
				if err != nil || string(body) != "keep" {
					t.Fatalf("unrelated data changed: %q, %v", body, err)
				}
			}
		})
	}
}

func TestResetStateRejectsSymlinkRoot(t *testing.T) {
	target := t.TempDir()
	store, err := OpenStore(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "state-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := ResetState(link); err == nil {
		t.Fatal("symlink reset succeeded")
	}
	if _, err := os.Stat(filepath.Join(target, "host.json")); err != nil {
		t.Fatalf("symlink reset changed target: %v", err)
	}
}

func TestResetStateAllowsSymlinkedParent(t *testing.T) {
	parent := t.TempDir()
	targetParent := filepath.Join(parent, "target")
	if err := os.Mkdir(targetParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkParent := filepath.Join(parent, "link")
	if err := os.Symlink(targetParent, linkParent); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	root := filepath.Join(linkParent, "state")
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ResetState(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(targetParent, "state", "host.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("host state remains after reset: %v", err)
	}
}

func TestResetStateRejectsLockedDirectory(t *testing.T) {
	root := t.TempDir()
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := ResetState(root); !errors.Is(err, ErrStateLocked) {
		t.Fatalf("reset error = %v, want ErrStateLocked", err)
	}
}

func TestOpenStoreFinishesInterruptedReset(t *testing.T) {
	root := t.TempDir()
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetCredentials("https://airlock.example", "credential", "host-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writeResetMarker(root); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(root, resetMarkerName))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("reset marker mode = %o, want 644", info.Mode().Perm())
		}
	}
	store, err = OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	airlockURL, credential := store.Credentials()
	if airlockURL != "" || credential != "" || store.HostID() != "" {
		t.Fatal("interrupted reset retained enrollment")
	}
}

func TestOpenStoreRejectsInvalidResetMarker(t *testing.T) {
	for _, marker := range []struct {
		name string
		make func(string) error
	}{
		{name: "content", make: func(path string) error { return os.WriteFile(path, []byte("resetting\n"), 0o600) }},
		{name: "directory", make: func(path string) error { return os.Mkdir(path, 0o700) }},
	} {
		t.Run(marker.name, func(t *testing.T) {
			root := t.TempDir()
			store, err := OpenStore(root)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if err := marker.make(filepath.Join(root, resetMarkerName)); err != nil {
				t.Fatal(err)
			}
			if store, err := OpenStore(root); err == nil {
				store.Close()
				t.Fatal("invalid reset marker accepted")
			}
			if _, err := os.Stat(filepath.Join(root, "host.json")); err != nil {
				t.Fatalf("invalid marker removed host state: %v", err)
			}
		})
	}
}

func TestOpenStoreRejectsResetMarkerFromAnotherRoot(t *testing.T) {
	source := t.TempDir()
	if err := writeResetMarker(source); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(source, resetMarkerName))
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	store, err := OpenStore(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, resetMarkerName), body, 0o644); err != nil {
		t.Fatal(err)
	}
	if store, err := OpenStore(target); err == nil {
		store.Close()
		t.Fatal("reset marker from another root accepted")
	}
	if _, err := os.Stat(filepath.Join(target, "host.json")); err != nil {
		t.Fatalf("foreign marker removed host state: %v", err)
	}
}

func TestResetStateRejectsUnrelatedHostJSON(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "host.json"), []byte(`{"application":"other"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "important"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ResetState(root); err == nil {
		t.Fatal("unrelated host.json accepted")
	}
	if body, err := os.ReadFile(filepath.Join(root, "important")); err != nil || string(body) != "keep" {
		t.Fatalf("unrelated data changed: %q, %v", body, err)
	}
}

func TestResetStateRejectsUnexpectedEntry(t *testing.T) {
	root := t.TempDir()
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetCredentials("https://airlock.example", "credential", "host-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "important"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ResetState(root); err == nil {
		t.Fatal("unexpected state entry accepted")
	}
	if body, err := os.ReadFile(filepath.Join(root, "important")); err != nil || string(body) != "keep" {
		t.Fatalf("unexpected entry changed: %q, %v", body, err)
	}
	if body, err := os.ReadFile(filepath.Join(root, "host.json")); err != nil || !strings.Contains(string(body), "credential") {
		t.Fatalf("host state changed before reset rejection: %q, %v", body, err)
	}
}

func TestResetStateDeletionRemainsBoundToOpenedRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("renaming an open directory is not portable on Windows")
	}
	parent := t.TempDir()
	root := filepath.Join(parent, "state")
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetCredentials("https://airlock.example", "credential", "host-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	bound, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	if err := writeResetMarkerToRoot(bound, root); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(parent, "moved")
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	const replacement = "replacement data"
	if err := os.WriteFile(filepath.Join(root, "host.json"), []byte(replacement), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := resetStateLocked(bound); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(root, "host.json"))
	if err != nil || string(body) != replacement {
		t.Fatalf("replacement root changed: %q, %v", body, err)
	}
	if _, err := os.Stat(filepath.Join(moved, "host.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("opened root host state remains: %v", err)
	}
}

func TestStoreContractSingleton(t *testing.T) {
	for _, method := range []string{"local", "remote", "plain"} {
		t.Run(method, func(t *testing.T) {
			store, err := OpenStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			put := store.PutConnector
			if method == "local" {
				put = store.PutLocalConnector
			}
			if method == "remote" {
				put = store.PutRemoteConnector
			}
			first := inventoryTestRecord(inventoryID)
			if err := put(first); err != nil {
				t.Fatal(err)
			}
			second := inventoryTestRecord(otherInventoryID)
			second.Manifest.Interface.ArtifactVersion = "different-version"
			second.Manifest.InterfaceHash, err = protocol.InterfaceDigest(second.Manifest.Interface)
			if err != nil {
				t.Fatal(err)
			}
			if err := put(second); err == nil || !strings.Contains(err.Error(), "duplicate installations") {
				t.Fatalf("duplicate admission = %v", err)
			}
			if err := store.admitConnector(second); err == nil {
				t.Fatal("prelaunch admission accepted duplicate")
			}
			if len(store.Connectors()) != 1 {
				t.Fatal("failed admission changed state")
			}
			second.InstallationID = first.InstallationID
			if err := put(second); err != nil {
				t.Fatalf("update: %v", err)
			}
			if err := store.RemoveRemoteConnector(first.InstallationID); err != nil {
				t.Fatal(err)
			}
			second.InstallationID = otherInventoryID
			if err := put(second); err != nil {
				t.Fatalf("admission after removal: %v", err)
			}
		})
	}
}

func TestStoreRejectsPersistedDuplicateContracts(t *testing.T) {
	root := t.TempDir()
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	first, second := inventoryTestRecord(inventoryID), inventoryTestRecord(otherInventoryID)
	store.state.Connectors = map[string]*ConnectorRecord{inventoryID: &first, otherInventoryID: &second}
	body, err := json.Marshal(store.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "host.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenStore(root); err == nil {
		reopened.Close()
		t.Fatal("persisted duplicates accepted")
	} else if !strings.Contains(err.Error(), inventoryID) || !strings.Contains(err.Error(), otherInventoryID) {
		t.Fatalf("error lacks remediation identities: %v", err)
	}
}

func TestPendingRemovalRejectsInstallationIDReuse(t *testing.T) {
	root := t.TempDir()
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	record := inventoryTestRecord(inventoryID)
	if err := store.PutRemoteConnector(record); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveLocalConnector(inventoryID); err != nil {
		t.Fatal(err)
	}
	removal := store.PendingInventoryMutations()[0]
	// The server can commit removal while its acknowledgement is lost.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	supervisor := NewSupervisor(store, nil)
	err = supervisor.Activate(t.Context(), record, func() error {
		t.Fatal("removed ID reached activation persistence")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "pending removal acknowledgement") {
		t.Fatalf("prelaunch admission: %v", err)
	}
	for name, put := range map[string]func(ConnectorRecord) error{"local": store.PutLocalConnector, "remote": store.PutRemoteConnector, "plain": store.PutConnector} {
		t.Run(name, func(t *testing.T) {
			if err := put(record); err == nil || !strings.Contains(err.Error(), "pending removal acknowledgement") {
				t.Fatalf("state admission: %v", err)
			}
			pending := store.PendingInventoryMutations()
			if len(pending) != 1 || !inventoryMutationsEqual(pending[0], removal) {
				t.Fatalf("removal overwritten: %+v", pending)
			}
		})
	}
	record.InstallationID = otherInventoryID
	if err := store.PutLocalConnector(record); err != nil {
		t.Fatalf("new installation ID: %v", err)
	}
	response := protocol.HostConnectorInventoryMutationResponse{InstallationID: inventoryID, AcknowledgedRevision: removal.Revision}
	if _, applied, err := store.AcknowledgeInventoryMutation(removal, response); err != nil || !applied {
		t.Fatalf("removal retry acknowledgement: %t, %v", applied, err)
	}
	pending := store.PendingInventoryMutations()
	if len(pending) != 1 || pending[0].InstallationID != otherInventoryID || pending[0].Kind != protocol.HostConnectorMutationUpsert {
		t.Fatalf("replacement inventory: %+v", pending)
	}
}

func TestSingletonContractScope(t *testing.T) {
	for _, contracts := range [][2]string{{"", ""}, {"example.first", "example.second"}} {
		t.Run(strings.Join(contracts[:], "/"), func(t *testing.T) {
			first, second := inventoryTestRecord(inventoryID), inventoryTestRecord(otherInventoryID)
			first.Manifest.Interface.ContractID, second.Manifest.Interface.ContractID = contracts[0], contracts[1]
			if err := validateSingletonContracts(map[string]*ConnectorRecord{inventoryID: &first, otherInventoryID: &second}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

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
	if err := store.SetAccessMode(AccessUpdates); err != nil {
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
	if store.AccessMode() != AccessUpdates || store.HostID() != "host-1" {
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

func TestStoreAccessModesPersist(t *testing.T) {
	for _, mode := range []AccessMode{AccessFull, AccessManage, AccessUpdates, AccessNone} {
		t.Run(string(mode), func(t *testing.T) {
			root := t.TempDir()
			store, err := OpenStore(root)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.SetAccessMode(mode); err != nil {
				t.Fatal(err)
			}
			for _, invalid := range []AccessMode{"unknown", "update_only", "manage_connectors"} {
				if err := store.SetAccessMode(invalid); err == nil {
					t.Fatalf("invalid mode %q accepted", invalid)
				}
			}
			if store.AccessMode() != mode {
				t.Fatal("invalid mode changed state")
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = OpenStore(root)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if store.AccessMode() != mode {
				t.Fatalf("reloaded mode = %q, want %q", store.AccessMode(), mode)
			}
		})
	}
}

func TestStoreAccessModeMigration(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, mode := range []AccessMode{AccessFull, "update_only", AccessNone} {
			t.Run(fmt.Sprintf("v%d/%s", version, mode), func(t *testing.T) {
				root := t.TempDir()
				record := inventoryTestRecord(inventoryID)
				record.PreviousDigest = record.ActiveDigest
				record.PreviousFilename = record.Filename
				record.PreviousSettings = record.Settings
				record.PreviousManifest = &record.Manifest
				state := persistedState{
					Version: version, AccessMode: mode, HostID: "host-1",
					AirlockURL: "https://airlock.example", Credential: "secret",
					Connectors:                map[string]*ConnectorRecord{inventoryID: &record},
					PendingInventoryMutations: make(map[string]protocol.HostConnectorInventoryMutationRequest),
				}
				if version == 2 {
					state.MutationRevision = 7
					state.PendingInventoryMutations[inventoryID] = inventoryUpsertMutation(record, 6)
					state.PendingInventoryMutations[otherInventoryID] = protocol.HostConnectorInventoryMutationRequest{
						InstallationID: otherInventoryID, Revision: 7, Kind: protocol.HostConnectorMutationRemove,
					}
				}
				body, err := json.Marshal(state)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(root, "host.json")
				if err := os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal(err)
				}
				state.Version = stateVersion
				if mode == "update_only" {
					state.AccessMode = AccessUpdates
				}
				if version == 1 {
					record.InventoryAcknowledged = true
				}
				for range 2 {
					store, err := OpenStore(root)
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(store.state, state) {
						t.Error("migration changed state beyond version, mode, and v1 inventory acknowledgement")
					}
					if err := store.Close(); err != nil {
						t.Fatal(err)
					}
					body, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					var persisted persistedState
					if err := json.Unmarshal(body, &persisted); err != nil {
						t.Fatal(err)
					}
					if persisted.Version != stateVersion || persisted.AccessMode != state.AccessMode {
						t.Fatal("migration was not persisted")
					}
				}
			})
		}
	}
}

func TestStoreRejectsInvalidPersistedAccessMode(t *testing.T) {
	for _, version := range []int{1, 2, stateVersion} {
		for _, mode := range []AccessMode{"manage_connectors", "unknown", "update_only"} {
			if version < stateVersion && mode == "update_only" {
				continue
			}
			t.Run(fmt.Sprintf("v%d/%s", version, mode), func(t *testing.T) {
				root := t.TempDir()
				body, err := json.Marshal(persistedState{Version: version, AccessMode: mode, Connectors: map[string]*ConnectorRecord{}})
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(root, "host.json")
				if err := os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal(err)
				}
				if store, err := OpenStore(root); err == nil {
					store.Close()
					t.Fatal("invalid persisted mode accepted")
				}
				persisted, err := os.ReadFile(path)
				if err != nil || string(persisted) != string(body) {
					t.Fatalf("failed migration modified state: %v", err)
				}
			})
		}
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
