package connectorhost

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

func TestManagementSurvivesSessionReconnect(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	gate := filepath.Join(t.TempDir(), "release-shell")
	input, err := json.Marshal(protocol.ShellInput{Command: executable, Environment: map[string]string{"AIRLOCK_CONNECTOR_HOST_TEST_SHELL_GATE": gate}, MaxOutputBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	var delivered atomic.Bool
	synced := make(chan struct{}, 10)
	completed := make(chan protocol.HostManagementCompletion, 10)
	server := controlTestServer(t, func(m protocol.HostMessage) protocol.HostMessage {
		switch {
		case m.Sync != nil:
			synced <- struct{}{}
			return protocol.HostMessage{Synced: &protocol.HostSyncResponse{HostID: "host", HeartbeatSeconds: 20}}
		case m.Demand != nil:
			if delivered.CompareAndSwap(false, true) {
				return protocol.HostMessage{Work: &protocol.HostWork{Kind: protocol.HostWorkShell, ManagementJob: &protocol.HostManagementJob{JobID: "shell", AttemptToken: "attempt", Input: input, Deadline: time.Now().Add(30 * time.Second)}}}
			}
			time.Sleep(10 * time.Millisecond)
		case m.ManagementCompletion != nil:
			completed <- *m.ManagementCompletion
		}
		return protocol.HostMessage{Ack: &struct{}{}}
	})
	if err := store.SetCredentials(server.URL, "credential", "host"); err != nil {
		t.Fatal(err)
	}
	host := newTestHost(store, server.Client())
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- host.serveRemote(ctx) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("host shutdown hung")
		}
	}()
	select {
	case <-synced:
	case <-time.After(5 * time.Second):
		t.Fatal("initial sync missing")
	}
	waitForTestPID(t, gate+".started")
	host.controlClient().Close()
	select {
	case <-synced:
	case <-time.After(5 * time.Second):
		t.Fatal("host did not reconnect")
	}
	if attempts := host.managementAttempts(); len(attempts) != 1 || attempts[0].AttemptToken != "attempt" {
		t.Fatalf("reconnect lost admitted management: %+v", attempts)
	}
	if err := os.WriteFile(gate, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-completed:
		if result.Status != "success" || result.AttemptToken != "attempt" {
			t.Fatalf("session disconnect canceled shell: %+v", result)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("shell did not complete across reconnect")
	}
}

func TestRemoteRemovalConfirmsAbsentInstallation(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host := NewHost(store, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := host.remove(t.Context(), inventoryID, false); err != nil {
		t.Fatalf("remote removal of failed install: %v", err)
	}
	if err := host.Remove(t.Context(), inventoryID); err == nil {
		t.Fatal("local removal of unknown installation succeeded")
	}
}

func TestRemoteManagementAbsentRemovalPolicy(t *testing.T) {
	for _, mode := range []AccessMode{AccessFull, AccessManage, AccessUpdates, AccessNone} {
		t.Run(string(mode), func(t *testing.T) {
			store, err := OpenStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if err := store.SetAccessMode(mode); err != nil {
				t.Fatal(err)
			}
			completed := make(chan protocol.HostManagementCompletion, 1)
			server := controlTestServer(t, func(message protocol.HostMessage) protocol.HostMessage {
				if message.ManagementCompletion != nil {
					completed <- *message.ManagementCompletion
				}
				return protocol.HostMessage{Ack: &struct{}{}}
			})
			host := newTestHost(store, server.Client())
			host.client = connectTestClient(t, server)
			host.handleManagement(t.Context(), protocol.HostWorkConnectorRemove, inventoryID, protocol.HostManagementJob{
				JobID: "remove", AttemptToken: "attempt", Deadline: time.Now().Add(5 * time.Second),
			})
			select {
			case completion := <-completed:
				if mode == AccessFull || mode == AccessManage {
					if completion.Status != "success" || completion.Error != "" {
						t.Fatalf("absent removal failed: %+v", completion)
					}
				} else if completion.Status != "error" || !strings.Contains(completion.Error, "local access policy denied") {
					t.Fatalf("absent removal not denied: %+v", completion)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("missing management completion")
			}
		})
	}
}

func TestAccessModeChangeIsLoggedAndWakesRemoteSync(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var output bytes.Buffer
	host := NewHost(store, nil, slog.New(slog.NewJSONHandler(&output, nil)))
	if err := host.SetAccessMode(AccessNone); err != nil {
		t.Fatal(err)
	}
	if store.AccessMode() != AccessNone {
		t.Fatalf("access mode = %q", store.AccessMode())
	}
	select {
	case <-host.stateChanged:
	default:
		t.Fatal("access mode change did not wake remote synchronization")
	}
	if log := output.String(); !strings.Contains(log, `"msg":"access mode changed"`) || !strings.Contains(log, `"current":"none"`) {
		t.Fatalf("log = %s", log)
	}
}

func TestRollbackSlotsSwappedIncludesSettingsForSameArtifact(t *testing.T) {
	activeManifest := protocol.Manifest{ArtifactDigest: "same", InterfaceHash: "active"}
	previousManifest := protocol.Manifest{ArtifactDigest: "same", InterfaceHash: "previous"}
	before := ConnectorRecord{
		ActiveDigest: "same", PreviousDigest: "same", Filename: "connector", PreviousFilename: "connector",
		Settings: json.RawMessage(`{"slot":"active"}`), PreviousSettings: json.RawMessage(`{"slot":"previous"}`),
		StorageOrigins: []string{"https://active.example"}, PreviousStorageOrigins: []string{"https://previous.example"},
		Manifest: activeManifest, PreviousManifest: &previousManifest,
	}
	if rollbackSlotsSwapped(before, before) {
		t.Fatal("unchanged same-digest slots were treated as a completed rollback")
	}
	current := ConnectorRecord{
		ActiveDigest: before.PreviousDigest, PreviousDigest: before.ActiveDigest,
		Filename: before.PreviousFilename, PreviousFilename: before.Filename,
		Settings: before.PreviousSettings, PreviousSettings: before.Settings,
		StorageOrigins: before.PreviousStorageOrigins, PreviousStorageOrigins: before.StorageOrigins,
		Manifest: previousManifest, PreviousManifest: &activeManifest,
	}
	if !rollbackSlotsSwapped(current, before) {
		t.Fatal("fully swapped same-digest slots were not recognized")
	}
}
