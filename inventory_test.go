package connectorhost

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

const (
	inventoryID      = "11111111-1111-4111-8111-111111111111"
	otherInventoryID = "22222222-2222-4222-8222-222222222222"
)

func TestInventoryMutationCrashReplayCoalescingAndRemoval(t *testing.T) {
	root := filepath.Join(t.TempDir(), "instance")
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	record := inventoryTestRecord(inventoryID)
	if err := store.PutLocalConnector(record); err != nil {
		t.Fatal(err)
	}
	first := store.PendingInventoryMutations()[0]
	record.DisplayName = "Latest display name"
	record.PreviousDigest = record.ActiveDigest
	record.PreviousFilename = record.Filename
	record.PreviousSettings = json.RawMessage(`{"old":true}`)
	previousManifest := record.Manifest
	record.PreviousManifest = &previousManifest
	if err := store.PutLocalConnector(record); err != nil {
		t.Fatal(err)
	}
	mutations := store.PendingInventoryMutations()
	if len(mutations) != 1 || mutations[0].Revision <= first.Revision || mutations[0].DisplayName != record.DisplayName || mutations[0].Rollback == nil {
		t.Fatalf("coalesced mutation = %+v, first revision = %d", mutations, first.Revision)
	}
	if mutations[0].Active.MeasuredDigest != record.ActiveDigest || mutations[0].Rollback.MeasuredDigest != record.PreviousDigest {
		t.Fatalf("observed artifacts = %+v / %+v", mutations[0].Active, mutations[0].Rollback)
	}
	staleResponse := protocol.HostConnectorInventoryMutationResponse{InstallationID: inventoryID, AcknowledgedRevision: first.Revision}
	if _, applied, err := store.AcknowledgeInventoryMutation(first, staleResponse); err != nil || applied {
		t.Fatalf("stale acknowledgement applied = %t, error = %v", applied, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	mutations = store.PendingInventoryMutations()
	if len(mutations) != 1 || mutations[0].Revision <= first.Revision {
		t.Fatalf("replayed mutations = %+v", mutations)
	}
	if err := store.RemoveLocalConnector(inventoryID); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	mutations = store.PendingInventoryMutations()
	if len(mutations) != 1 || mutations[0].Kind != protocol.HostConnectorMutationRemove || mutations[0].Revision <= first.Revision {
		t.Fatalf("removal tombstone = %+v", mutations)
	}
	if _, exists := store.Connector(inventoryID); exists {
		t.Fatal("removed connector record remains")
	}
	response := protocol.HostConnectorInventoryMutationResponse{InstallationID: inventoryID, AcknowledgedRevision: mutations[0].Revision}
	if _, applied, err := store.AcknowledgeInventoryMutation(mutations[0], response); err != nil || !applied {
		t.Fatalf("tombstone acknowledgement applied = %t, error = %v", applied, err)
	}
	if pending := store.PendingInventoryMutations(); len(pending) != 0 {
		t.Fatalf("acknowledged tombstone remains: %+v", pending)
	}
}

func TestInventoryMutationLostResponseRetriesAndDoesNotBlockOthers(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "instance"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, id := range []string{inventoryID, otherInventoryID} {
		if err := store.PutLocalConnector(inventoryTestRecord(id)); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	requests := make(map[string][]protocol.HostConnectorInventoryMutationRequest)
	failedOnce := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var mutation protocol.HostConnectorInventoryMutationRequest
		if request.URL.Path != "/api/hosts/v1/connectors/inventory" || request.Header.Get("Authorization") != "Bearer credential" || json.NewDecoder(request.Body).Decode(&mutation) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		mu.Lock()
		requests[mutation.InstallationID] = append(requests[mutation.InstallationID], mutation)
		fail := mutation.InstallationID == inventoryID && !failedOnce
		if fail {
			failedOnce = true
		}
		mu.Unlock()
		if fail {
			http.Error(w, "response lost", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(protocol.HostConnectorInventoryMutationResponse{InstallationID: mutation.InstallationID, AcknowledgedRevision: mutation.Revision})
	}))
	defer server.Close()
	client, err := NewControlClient(server.URL, "credential", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	host := NewHost(store, server.Client())
	host.flushInventoryMutations(t.Context(), client)
	pending := store.PendingInventoryMutations()
	if len(pending) != 1 || pending[0].InstallationID != inventoryID {
		t.Fatalf("pending after partial failure = %+v", pending)
	}
	host.flushInventoryMutations(t.Context(), client)
	if pending := store.PendingInventoryMutations(); len(pending) != 0 {
		t.Fatalf("pending after retry = %+v", pending)
	}
	mu.Lock()
	replayed := append([]protocol.HostConnectorInventoryMutationRequest(nil), requests[inventoryID]...)
	mu.Unlock()
	if len(replayed) != 2 || !inventoryMutationsEqual(replayed[0], replayed[1]) {
		t.Fatalf("lost-response replay = %+v", replayed)
	}
}

func TestInventoryCoalescingPreservesConcurrentAcknowledgement(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "instance"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	before := inventoryTestRecord(inventoryID)
	if err := store.PutLocalConnector(before); err != nil {
		t.Fatal(err)
	}
	mutation := store.PendingInventoryMutations()[0]
	stagedUpdate := cloneRecord(before)
	stagedUpdate.Settings = json.RawMessage(`{"updated":true}`)
	stagedUpdate.PreviousDigest = before.ActiveDigest
	stagedUpdate.PreviousFilename = before.Filename
	stagedUpdate.PreviousSettings = before.Settings
	previousManifest := before.Manifest
	stagedUpdate.PreviousManifest = &previousManifest
	origins := []string{"https://storage.example"}
	response := protocol.HostConnectorInventoryMutationResponse{InstallationID: inventoryID, AcknowledgedRevision: mutation.Revision, StorageOrigins: origins}
	if _, applied, err := store.AcknowledgeInventoryMutation(mutation, response); err != nil || !applied {
		t.Fatalf("acknowledgement applied = %t, error = %v", applied, err)
	}
	if err := store.PutLocalConnector(stagedUpdate); err != nil {
		t.Fatal(err)
	}
	current, exists := store.Connector(inventoryID)
	if !exists || !current.InventoryAcknowledged || !slices.Equal(current.PreviousStorageOrigins, origins) {
		t.Fatalf("coalesced record lost acknowledgement: %+v", current)
	}
	pending := store.PendingInventoryMutations()
	if len(pending) != 1 || pending[0].Revision <= mutation.Revision || pending[0].Rollback == nil {
		t.Fatalf("coalesced pending mutation = %+v", pending)
	}
}

func TestInventoryAcknowledgementRestartsWithPersistedStorageOrigins(t *testing.T) {
	tests := []struct {
		name        string
		active      bool
		rejected    bool
		spontaneous bool
	}{
		{name: "active", active: true},
		{name: "rejected", rejected: true},
		{name: "spontaneous readiness", spontaneous: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenStore(filepath.Join(t.TempDir(), "instance"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if err := store.SetAccessMode(AccessNone); err != nil {
				t.Fatal(err)
			}
			host := NewHost(store, nil)
			t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_CHILD", "1")
			appliedPath := filepath.Join(t.TempDir(), "origins.json")
			pidPath := filepath.Join(t.TempDir(), "initialize.pid")
			settingsPath := filepath.Join(t.TempDir(), "settings.json")
			t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_INITIALIZE_PATH", appliedPath)
			t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_INITIALIZE_PID_PATH", pidPath)
			t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_SETTINGS_PATH", settingsPath)
			t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_REJECT_SETTINGS", "1")
			if test.active {
				t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_BLOCK_JOBS", "1")
			}
			if test.rejected {
				t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_REJECT_INITIALIZE_ORIGINS", "1")
			}
			spontaneousPath := filepath.Join(t.TempDir(), "spontaneous")
			if test.spontaneous {
				t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_SPONTANEOUS_READY_PATH", spontaneousPath)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			installed, err := host.LocalInstall(ctx, LocalInstallRequest{InstallationID: inventoryID, SourcePath: executable, DisplayName: "Local helper"})
			if err != nil {
				t.Fatal(err)
			}
			initialPID := waitForTestPID(t, pidPath)
			if installed.InstallationID != inventoryID || len(host.syncRequest().Connectors) != 0 {
				t.Fatalf("unacknowledged install heartbeat = %+v", host.syncRequest().Connectors)
			}
			if test.active {
				job := protocol.JobRequest{JobID: "active-job", AttemptToken: "active-attempt", Kind: protocol.JobKindCommand, Input: json.RawMessage(`{}`), Deadline: time.Now().Add(time.Minute)}
				if err := host.supervisor.Dispatch(inventoryID, job); err != nil {
					t.Fatal(err)
				}
			}
			if test.spontaneous {
				if err := os.WriteFile(spontaneousPath, []byte("ready"), 0o600); err != nil {
					t.Fatal(err)
				}
				waitForTestFile(t, spontaneousPath+".sent")
			}
			origins := []string{"https://storage.example"}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				var mutation protocol.HostConnectorInventoryMutationRequest
				if json.NewDecoder(request.Body).Decode(&mutation) != nil {
					http.Error(w, "bad mutation", http.StatusBadRequest)
					return
				}
				_ = json.NewEncoder(w).Encode(protocol.HostConnectorInventoryMutationResponse{InstallationID: mutation.InstallationID, AcknowledgedRevision: mutation.Revision, StorageOrigins: origins})
			}))
			defer server.Close()
			client, err := NewControlClient(server.URL, "credential", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			host.flushInventoryMutations(ctx, client)
			waitForDifferentTestPID(t, pidPath, initialPID)
			persisted, exists := store.Connector(inventoryID)
			if !exists || !persisted.InventoryAcknowledged || !slices.Equal(persisted.StorageOrigins, origins) || len(host.syncRequest().Connectors) != 1 {
				t.Fatalf("acknowledged record = %+v, heartbeat = %+v", persisted, host.syncRequest().Connectors)
			}
			if _, err := os.Stat(settingsPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("live settings path was used: %v", err)
			}
			statuses := host.supervisor.Statuses()
			if test.rejected {
				if len(statuses) != 1 || statuses[0].Readiness != protocol.ReadinessOffline || statuses[0].Error == "" {
					t.Fatalf("rejected restart status = %+v", statuses)
				}
			} else {
				waitForTestOrigins(t, appliedPath, origins)
				if len(statuses) != 1 || statuses[0].Readiness != protocol.ReadinessReady {
					t.Fatalf("restarted status = %+v", statuses)
				}
			}
			if !host.managementMu.TryLock() {
				t.Fatal("inventory restart left host management serialization locked")
			}
			host.managementMu.Unlock()
			stopCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			if err := host.Close(stopCtx); err != nil {
				stop()
				t.Fatal(err)
			}
			stop()
		})
	}
}

func waitForDifferentTestPID(t *testing.T, path string, previous int) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		body, err := os.ReadFile(path)
		pid, parseErr := strconv.Atoi(string(body))
		if err == nil && parseErr == nil && pid > 0 && pid != previous {
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("restarted connector PID was not written: %q, %v", body, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForTestOrigins(t *testing.T, path string, expected []string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		body, err := os.ReadFile(path)
		var observed []string
		if err == nil && json.Unmarshal(body, &observed) == nil && slices.Equal(observed, expected) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("connector origins = %q, error = %v", body, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForTestFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("test file %q was not written", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRemoteLifecycleDoesNotCreateLocalInventoryMutations(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "instance"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record := inventoryTestRecord(inventoryID)
	if err := store.PutLocalConnector(record); err != nil {
		t.Fatal(err)
	}
	record.DisplayName = "Remote reconciliation"
	if err := store.PutRemoteConnector(record); err != nil {
		t.Fatal(err)
	}
	if pending := store.PendingInventoryMutations(); len(pending) != 0 {
		t.Fatalf("remote upsert left local mutations: %+v", pending)
	}
	if err := store.RemoveRemoteConnector(inventoryID); err != nil {
		t.Fatal(err)
	}
	if pending := store.PendingInventoryMutations(); len(pending) != 0 {
		t.Fatalf("remote removal created a tombstone: %+v", pending)
	}
}

func inventoryTestRecord(id string) ConnectorRecord {
	manifest := helperManifest()
	return ConnectorRecord{
		InstallationID: id,
		DisplayName:    "Inventory helper",
		ActiveDigest:   manifest.ArtifactDigest,
		Filename:       "helper",
		Settings:       json.RawMessage(`{}`),
		Manifest:       manifest,
		InstalledAt:    time.Now().UTC(),
	}
}
