package connectorhost

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

func TestPollStopsWhenAccessModeChanges(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		close(started)
		<-release
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})
	client, err := NewControlClient(server.URL, "credential", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host := NewHost(store, server.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	result := make(chan bool, 1)
	go func() {
		_, _, changed := host.poll(context.Background(), client, time.Minute)
		result <- changed
	}()
	<-started
	if err := host.SetAccessMode(AccessNone); err != nil {
		t.Fatal(err)
	}
	select {
	case changed := <-result:
		if !changed {
			t.Fatal("poll did not report an access mode change")
		}
	case <-time.After(time.Second):
		t.Fatal("poll did not stop after an access mode change")
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
