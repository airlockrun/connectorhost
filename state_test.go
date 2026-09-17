package connectorhost

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

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
