package connectorhost

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

func TestControlClientUsesHostEndpointsAndBearerCredential(t *testing.T) {
	var path, authorization string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, authorization = r.URL.Path, r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(protocol.HostSyncResponse{HostID: "host-1", HeartbeatSeconds: 30})
	}))
	defer server.Close()
	client, err := NewControlClient(server.URL, "credential", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Sync(context.Background(), protocol.HostSyncRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/api/hosts/v1/sync" || authorization != "Bearer credential" || response.HostID != "host-1" {
		t.Fatalf("request = %q %q, response = %+v", path, authorization, response)
	}
}

func TestControlClientRejectsNonHTTPSOrigin(t *testing.T) {
	if _, err := NewControlClient("http://airlock.example", "credential", nil); err == nil {
		t.Fatal("HTTP origin accepted")
	}
}

func TestControlClientValidatesInventoryMutationResponse(t *testing.T) {
	request := inventoryUpsertMutation(inventoryTestRecord(inventoryID), 7)
	tests := []struct {
		name     string
		response protocol.HostConnectorInventoryMutationResponse
	}{
		{"wrong revision", protocol.HostConnectorInventoryMutationResponse{InstallationID: inventoryID, AcknowledgedRevision: 8}},
		{"invalid origin", protocol.HostConnectorInventoryMutationResponse{InstallationID: inventoryID, AcknowledgedRevision: 7, StorageOrigins: []string{"http://storage.example"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/hosts/v1/connectors/inventory" || r.Header.Get("Authorization") != "Bearer credential" {
					http.Error(w, "wrong request", http.StatusBadRequest)
					return
				}
				_ = json.NewEncoder(w).Encode(test.response)
			}))
			defer server.Close()
			client, err := NewControlClient(server.URL, "credential", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.InventoryMutation(t.Context(), request); err == nil {
				t.Fatal("invalid inventory response accepted")
			}
		})
	}
}
