package connectorhost

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
	"github.com/coder/websocket"
)

func controlTestServer(t *testing.T, handle func(protocol.HostMessage) protocol.HostMessage) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/hosts/v1/connect" || r.Header.Get("Authorization") != "Bearer credential" {
			http.Error(w, "bad request", 400)
			return
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{protocol.HostTransportProtocol}})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		conn.SetReadLimit(protocol.MaxHostMessageBytes)
		for {
			_, data, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			message, err := protocol.DecodeHostMessage(data)
			if err != nil {
				t.Error(err)
				return
			}
			response := handle(message)
			response.Protocol, response.ID = protocol.HostTransportProtocol, message.ID
			body, err := json.Marshal(response)
			if err != nil {
				t.Error(err)
				return
			}
			if err := conn.Write(r.Context(), websocket.MessageText, body); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func connectTestClient(t *testing.T, server *httptest.Server) *ControlClient {
	t.Helper()
	client, err := NewControlClient(server.URL, "credential", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func TestControlClientMultiplexesOneAuthenticatedSession(t *testing.T) {
	server := controlTestServer(t, func(m protocol.HostMessage) protocol.HostMessage {
		if m.Sync != nil {
			return protocol.HostMessage{Synced: &protocol.HostSyncResponse{HostID: "host-1", HeartbeatSeconds: 20}}
		}
		return protocol.HostMessage{Ack: &struct{}{}}
	})
	client := connectTestClient(t, server)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			response, err := client.Sync(t.Context(), protocol.HostSyncRequest{})
			if err != nil || response.HostID != "host-1" {
				t.Errorf("Sync = %+v, %v", response, err)
			}
		})
	}
	workers.Wait()
	if err := client.Heartbeat(t.Context(), protocol.HostHeartbeat{}); err != nil {
		t.Fatal(err)
	}
}

func TestControlClientRejectsNonHTTPSOrigin(t *testing.T) {
	if _, err := NewControlClient("http://airlock.example", "credential", nil); err == nil {
		t.Fatal("HTTP accepted")
	}
}

func TestControlClientValidatesInventoryMutationResponse(t *testing.T) {
	request := inventoryUpsertMutation(inventoryTestRecord(inventoryID), 7)
	for _, test := range []struct {
		name     string
		response protocol.HostConnectorInventoryMutationResponse
	}{
		{"wrong revision", protocol.HostConnectorInventoryMutationResponse{InstallationID: inventoryID, AcknowledgedRevision: 8}},
		{"invalid origin", protocol.HostConnectorInventoryMutationResponse{InstallationID: inventoryID, AcknowledgedRevision: 7, StorageOrigins: []string{"http://storage.example"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := controlTestServer(t, func(protocol.HostMessage) protocol.HostMessage {
				return protocol.HostMessage{Inventoried: &test.response}
			})
			client := connectTestClient(t, server)
			if _, err := client.InventoryMutation(t.Context(), request); err == nil {
				t.Fatal("invalid inventory response accepted")
			}
		})
	}
}

func TestControlClientCancellationClosesOutstandingDemand(t *testing.T) {
	release := make(chan struct{})
	server := controlTestServer(t, func(protocol.HostMessage) protocol.HostMessage {
		<-release
		return protocol.HostMessage{Ack: &struct{}{}}
	})
	defer close(release)
	client := connectTestClient(t, server)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := client.Demand(ctx, 1); err == nil {
		t.Fatal("canceled demand succeeded")
	}
	client.Close()
}
