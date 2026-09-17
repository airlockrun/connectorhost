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
	"sync/atomic"
	"testing"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
	"github.com/google/uuid"
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
		record := inventoryTestRecord(id)
		record.Manifest.Interface.ContractID += "." + id
		record.Manifest.InterfaceHash, err = protocol.InterfaceDigest(record.Manifest.Interface)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.PutLocalConnector(record); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	requests := make(map[string][]protocol.HostConnectorInventoryMutationRequest)
	failedOnce := false
	server := controlTestServer(t, func(message protocol.HostMessage) protocol.HostMessage {
		mutation := *message.Inventory
		mu.Lock()
		requests[mutation.InstallationID] = append(requests[mutation.InstallationID], mutation)
		fail := mutation.InstallationID == inventoryID && !failedOnce
		if fail {
			failedOnce = true
		}
		mu.Unlock()
		if fail {
			return protocol.HostMessage{Error: &protocol.HostMessageError{Code: 500, Message: "response lost"}}
		}
		return protocol.HostMessage{Inventoried: &protocol.HostConnectorInventoryMutationResponse{InstallationID: mutation.InstallationID, AcknowledgedRevision: mutation.Revision}}
	})
	client := connectTestClient(t, server)
	host := newTestHost(store, server.Client())
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
			host := newTestHost(store, nil)
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
			server := controlTestServer(t, func(message protocol.HostMessage) protocol.HostMessage {
				mutation := *message.Inventory
				return protocol.HostMessage{Inventoried: &protocol.HostConnectorInventoryMutationResponse{InstallationID: mutation.InstallationID, AcknowledgedRevision: mutation.Revision, StorageOrigins: origins}}
			})
			client := connectTestClient(t, server)
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

func TestRemoteInstallAndRemovalUseManagementInventory(t *testing.T) {
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

func TestRemoteTransitionsReplayCompletionBeforeInventory(t *testing.T) {
	for _, kind := range []protocol.HostWorkKind{protocol.HostWorkConnectorUpdate, protocol.HostWorkConnectorRollback} {
		t.Run(string(kind), func(t *testing.T) {
			root := t.TempDir()
			store, err := OpenStore(root)
			if err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(executable)
			if err != nil {
				t.Fatal(err)
			}
			body = append(body, []byte("remote-update-regression")...)
			candidatePath := filepath.Join(t.TempDir(), filepath.Base(executable))
			if err := os.WriteFile(candidatePath, body, 0o700); err != nil {
				t.Fatal(err)
			}
			installer := NewArtifactInstaller(store, nil)
			before, err := installer.StageLocal(t.Context(), LocalArtifactInput{InstallationID: inventoryID, SourcePath: executable, DisplayName: "Managed helper"})
			if err != nil {
				t.Fatal(err)
			}
			after, err := installer.StageLocal(t.Context(), LocalArtifactInput{InstallationID: inventoryID, SourcePath: candidatePath, DisplayName: before.DisplayName})
			if err != nil {
				t.Fatal(err)
			}
			if kind == protocol.HostWorkConnectorRollback {
				before.PreviousDigest, before.PreviousFilename = after.ActiveDigest, after.Filename
				before.PreviousSettings, before.PreviousManifest = after.Settings, &after.Manifest
			}
			if err := store.PutRemoteConnector(before); err != nil {
				t.Fatal(err)
			}
			artifactServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
			defer artifactServer.Close()
			jobID, token := uuid.NewString(), uuid.NewString()
			var allowCompletion atomic.Bool
			var loseInventory atomic.Bool
			loseInventory.Store(true)
			var mu sync.Mutex
			var completions []protocol.HostManagementCompletion
			var mutations []protocol.HostConnectorInventoryMutationRequest
			server := controlTestServer(t, func(message protocol.HostMessage) protocol.HostMessage {
				mu.Lock()
				defer mu.Unlock()
				if message.ManagementCompletion != nil {
					completions = append(completions, *message.ManagementCompletion)
					if !allowCompletion.Load() {
						return protocol.HostMessage{}
					}
				}
				if message.Inventory != nil {
					mutations = append(mutations, *message.Inventory)
					if loseInventory.Swap(false) {
						return protocol.HostMessage{}
					}
					return protocol.HostMessage{Inventoried: &protocol.HostConnectorInventoryMutationResponse{InstallationID: inventoryID, AcknowledgedRevision: message.Inventory.Revision}}
				}
				return protocol.HostMessage{Ack: &struct{}{}}
			})
			t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_CHILD", "1")
			host := newTestHost(store, artifactServer.Client())
			host.client = connectTestClient(t, server)
			input, _ := json.Marshal(protocol.ConnectorArtifactInput{InstallationID: inventoryID, URL: artifactServer.URL, Filename: after.Filename, SHA256: after.ActiveDigest, SizeBytes: int64(len(body))})
			host.handleManagement(t.Context(), kind, inventoryID, protocol.HostManagementJob{JobID: jobID, AttemptToken: token, Input: input, Deadline: time.Now().Add(time.Minute)})
			pending := store.PendingInventoryMutations()
			if len(pending) != 1 || pending[0].ManagementAttempt == nil || pending[0].ManagementAttempt.AttemptToken != token || pending[0].Active.MeasuredDigest != after.ActiveDigest || pending[0].Rollback == nil || pending[0].Rollback.MeasuredDigest != before.ActiveDigest {
				t.Fatalf("activated inventory = %+v", pending)
			}
			if len(host.syncRequest().Connectors) != 0 {
				t.Fatal("unacknowledged remote artifact entered compact sync")
			}
			host.flushInventoryMutations(t.Context(), host.client)
			mu.Lock()
			early := len(mutations)
			mu.Unlock()
			if early != 0 {
				t.Fatal("inventory overtook lost completion acknowledgement")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			if err := host.Close(ctx); err != nil {
				t.Fatal(err)
			}
			cancel()
			host.client.Close()
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = OpenStore(root)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			host = newTestHost(store, server.Client())
			defer func() {
				ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if err := host.Close(ctx); err != nil {
					t.Error(err)
				}
			}()
			host.client = connectTestClient(t, server)
			if err := host.supervisor.StartAll(t.Context()); err != nil {
				t.Fatal(err)
			}
			if len(host.syncRequest().Connectors) != 0 {
				t.Fatal("restart lost inventory acknowledgement fence")
			}
			allowCompletion.Store(true)
			host.flushManagementOutcomes(t.Context())
			host.flushInventoryMutations(t.Context(), host.client)
			if len(store.PendingInventoryMutations()) != 1 {
				t.Fatal("lost inventory ACK discarded mutation")
			}
			host.client.Close()
			if err := host.client.Connect(t.Context()); err != nil {
				t.Fatal(err)
			}
			host.flushInventoryMutations(t.Context(), host.client)
			if len(store.PendingInventoryMutations()) != 0 || len(host.syncRequest().Connectors) != 1 {
				t.Fatal("acknowledged artifact did not become reportable")
			}
			mu.Lock()
			defer mu.Unlock()
			if len(completions) != 2 || completions[0].Status != "success" || completions[0].InventoryRevision != pending[0].Revision {
				t.Fatalf("completions = %+v", completions)
			}
			first, _ := json.Marshal(completions[0])
			second, _ := json.Marshal(completions[1])
			if string(first) != string(second) {
				t.Fatal("completion replay changed its durable revision")
			}
			if len(mutations) != 2 || !inventoryMutationsEqual(mutations[0], mutations[1]) {
				t.Fatalf("inventory replay changed: %+v", mutations)
			}
		})
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

func TestRemoteTransitionRecoveryPreservesInventoryRevision(t *testing.T) {
	for _, kind := range []protocol.HostWorkKind{protocol.HostWorkConnectorUpdate, protocol.HostWorkConnectorRollback} {
		t.Run(string(kind), func(t *testing.T) {
			root := t.TempDir()
			store, err := OpenStore(root)
			if err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			before, err := NewArtifactInstaller(store, nil).StageLocal(t.Context(), LocalArtifactInput{InstallationID: inventoryID, SourcePath: executable, DisplayName: "Managed", Settings: json.RawMessage(`{"slot":"before"}`)})
			if err != nil {
				t.Fatal(err)
			}
			before.PreviousDigest, before.PreviousFilename = before.ActiveDigest, before.Filename
			previousManifest := before.Manifest
			before.PreviousManifest, before.PreviousSettings = &previousManifest, json.RawMessage(`{"slot":"after"}`)
			if err := store.PutRemoteConnector(before); err != nil {
				t.Fatal(err)
			}
			attempt := protocol.ActiveAttempt{JobID: uuid.NewString(), AttemptToken: uuid.NewString()}
			if err := store.saveManagementOutcome(managementOutcome{JobID: attempt.JobID, AttemptToken: attempt.AttemptToken, Kind: kind, ConnectorID: inventoryID, Status: "running", ConnectorExisted: true, ConnectorBefore: &before}); err != nil {
				t.Fatal(err)
			}
			after := cloneRecord(before)
			after.Settings, after.PreviousSettings = before.PreviousSettings, before.Settings
			if err := store.PutRemoteTransition(after, attempt); err != nil {
				t.Fatal(err)
			}
			revision := store.PendingInventoryMutations()[0].Revision
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = OpenStore(root)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_CHILD", "1")
			host := newTestHost(store, nil)
			defer func() {
				ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if err := host.Close(ctx); err != nil {
					t.Error(err)
				}
			}()
			if err := host.recoverInterruptedManagement(t.Context()); err != nil {
				t.Fatal(err)
			}
			outcome, found, err := store.loadManagementOutcome(attempt.JobID)
			if err != nil || !found || outcome.Status != "success" || outcome.InventoryRevision != revision {
				t.Fatalf("recovered transition = %+v, %v", outcome, err)
			}
			pending := store.PendingInventoryMutations()
			if len(pending) != 1 || pending[0].Revision != revision || pending[0].ManagementAttempt == nil || *pending[0].ManagementAttempt != attempt {
				t.Fatalf("recovery changed inventory fence: %+v", pending)
			}
			if len(host.syncRequest().Connectors) != 0 {
				t.Fatal("recovery advertised unacknowledged metadata")
			}
		})
	}
}
