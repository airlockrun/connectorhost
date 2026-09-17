package connectorhost

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

func TestRejectedRetentionDoesNotConsumePendingCapacity(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host := newTestHost(store, nil)
	var reject atomic.Bool
	reject.Store(true)
	server := controlTestServer(t, func(protocol.HostMessage) protocol.HostMessage {
		if reject.Load() {
			return protocol.HostMessage{Error: &protocol.HostMessageError{Code: 409, Message: "stale attempt"}}
		}
		return protocol.HostMessage{Ack: &struct{}{}}
	})
	host.client = connectTestClient(t, server)
	for i := range maxOutboxEntries + 1 {
		if err := host.ConnectorCompletion(t.Context(), "connector", fmt.Sprint(i), protocol.JobCompletion{AttemptToken: "attempt", Status: "error", Error: "failed"}); err != nil {
			t.Fatal(err)
		}
		if err := host.flushConnectorOutcomes(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(store.root, "outbox"))
	if err != nil || len(entries) != maxRejectedEntries {
		t.Fatalf("retained rejections = %d, %v", len(entries), err)
	}
	for sequence := int64(1); sequence <= maxOutboxEntries-protocol.MaxHostConnectorClaims; sequence++ {
		if err := host.ConnectorEvent(t.Context(), "connector", "fresh", protocol.JobEvent{AttemptToken: "fresh", Sequence: sequence}); err != nil {
			t.Fatalf("rejections consumed pending capacity: %v", err)
		}
	}
	reject.Store(false)
	if err := host.flushConnectorOutcomes(t.Context()); err != nil {
		t.Fatal(err)
	}
	entries, err = os.ReadDir(filepath.Join(store.root, "outbox"))
	if err != nil || len(entries) != maxRejectedEntries {
		t.Fatalf("valid output not drained: %d, %v", len(entries), err)
	}
	select {
	case err := <-host.outputFailure:
		t.Fatalf("rejections stopped host: %v", err)
	default:
	}
}

func TestRejectedRetentionBoundsBytes(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host := newTestHost(store, nil)
	directory := filepath.Join(store.root, "outbox")
	for i := range 20 {
		if err := atomicWrite(filepath.Join(directory, fmt.Sprintf("%03d.rejected", i)), make([]byte, 1<<20), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	host.outboxMu.Lock()
	err = host.pruneRejectedOutcomes(directory)
	host.outboxMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var size int64
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		size += info.Size()
	}
	if size > maxRejectedBytes || len(entries) >= 20 {
		t.Fatalf("unbounded retention: %d bytes, %d entries", size, len(entries))
	}
}

func TestOutboxPersistsWithoutNetworkAndReplaysLostAcknowledgement(t *testing.T) {
	root := t.TempDir()
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	host := newTestHost(store, nil)
	event := protocol.JobEvent{AttemptToken: "attempt", Sequence: 1, Message: "working"}
	completion := protocol.JobCompletion{AttemptToken: "attempt", Status: "success", Output: json.RawMessage(`{"result":42}`)}
	if err := host.ConnectorEvent(t.Context(), "connector", "job", event); err != nil {
		t.Fatal(err)
	}
	if err := host.ConnectorCompletion(t.Context(), "connector", "job", completion); err != nil {
		t.Fatal(err)
	}
	attempts, err := host.activeAttempts()
	if err != nil || len(attempts) != 1 || attempts[0].AttemptToken != "attempt" {
		t.Fatalf("pending completion renewal = %+v, %v", attempts, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host = newTestHost(store, nil)
	var mu sync.Mutex
	var received []protocol.HostMessage
	lost := false
	server := controlTestServer(t, func(message protocol.HostMessage) protocol.HostMessage {
		mu.Lock()
		defer mu.Unlock()
		received = append(received, message)
		if message.ConnectorCompletion != nil && !lost {
			lost = true
			// An invalid reply closes the client session after server commit.
			return protocol.HostMessage{}
		}
		return protocol.HostMessage{Ack: &struct{}{}}
	})
	client := connectTestClient(t, server)
	host.client = client
	if err := host.flushConnectorOutcomes(t.Context()); err == nil {
		t.Fatal("lost acknowledgement was accepted")
	}
	client.Close()
	if err := client.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := host.flushConnectorOutcomes(t.Context()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(received) != 3 || received[0].ConnectorEvent == nil || received[1].ConnectorCompletion == nil || received[2].ConnectorCompletion == nil {
		t.Fatalf("replayed output = %+v", received)
	}
	first, _ := json.Marshal(received[1].ConnectorCompletion)
	second, _ := json.Marshal(received[2].ConnectorCompletion)
	if string(first) != string(second) {
		t.Fatal("completion replay changed its payload")
	}
	entries, err := os.ReadDir(filepath.Join(root, "outbox"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("acknowledged outbox = %v, %v", entries, err)
	}
}

func TestOutboxRejectsConflictingCompletionAndSignalsFailure(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host := newTestHost(store, nil)
	completion := protocol.JobCompletion{AttemptToken: "attempt", Status: "success", Output: json.RawMessage(`{}`)}
	if err := host.ConnectorCompletion(t.Context(), "connector", "job", completion); err != nil {
		t.Fatal(err)
	}
	if err := host.ConnectorCompletion(t.Context(), "connector", "job", completion); err != nil {
		t.Fatal(err)
	}
	completion.Output = json.RawMessage(`{"changed":true}`)
	if err := host.ConnectorCompletion(t.Context(), "connector", "job", completion); err == nil {
		t.Fatal("conflicting outcome replaced durable completion")
	}
	select {
	case <-host.outputFailure:
	default:
		t.Fatal("durability failure did not stop host admission")
	}
}

func TestOutboxReservesCompletionCapacity(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host := newTestHost(store, nil)
	for sequence := int64(1); sequence <= maxOutboxEntries-protocol.MaxHostConnectorClaims; sequence++ {
		if err := host.ConnectorEvent(t.Context(), "connector", "job", protocol.JobEvent{AttemptToken: "attempt", Sequence: sequence}); err != nil {
			t.Fatal(err)
		}
	}
	if err := host.ConnectorEvent(t.Context(), "connector", "job", protocol.JobEvent{AttemptToken: "attempt", Sequence: maxOutboxEntries}); err == nil {
		t.Fatal("unbounded event queue")
	}
	if err := host.ConnectorCompletion(t.Context(), "connector", "job", protocol.JobCompletion{AttemptToken: "attempt", Status: "error", Error: "output queue full"}); err != nil {
		t.Fatalf("terminal reserve unavailable: %v", err)
	}
}

func TestOutboxRetainsExplicitlyRejectedOutput(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host := newTestHost(store, nil)
	if err := host.ConnectorCompletion(t.Context(), "connector", "job", protocol.JobCompletion{AttemptToken: "attempt", Status: "error", Error: "failed"}); err != nil {
		t.Fatal(err)
	}
	server := controlTestServer(t, func(protocol.HostMessage) protocol.HostMessage {
		return protocol.HostMessage{Error: &protocol.HostMessageError{Code: 409, Message: "stale attempt"}}
	})
	host.client = connectTestClient(t, server)
	if err := host.flushConnectorOutcomes(t.Context()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(store.root, "outbox"))
	if err != nil || len(entries) != 1 || filepath.Ext(entries[0].Name()) != ".rejected" {
		t.Fatalf("rejected output = %v, %v", entries, err)
	}
	attempts, err := host.activeAttempts()
	if err != nil || len(attempts) != 0 {
		t.Fatalf("rejected output still consumes capacity: %+v, %v", attempts, err)
	}
}
