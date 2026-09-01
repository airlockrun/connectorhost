package connectorhost

import (
	"encoding/json"
	"testing"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

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
