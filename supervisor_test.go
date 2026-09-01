package connectorhost

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

func TestChildInitializationWriteHonorsDeadline(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "instance"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record := stageSupervisorTestConnector(t, store, "blocked-initialize", json.RawMessage(`"`+strings.Repeat("x", 900<<10)+`"`))
	if err := store.PutConnector(record); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_CHILD", "1")
	t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_NO_STDIN", "1")
	supervisor := NewSupervisor(store, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	started := time.Now()
	err = supervisor.Start(ctx, record.InstallationID)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("start error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("blocked initialization returned after %s", elapsed)
	}
}

func TestChildCancellationWritesHonorShutdownDeadline(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "instance"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record := stageSupervisorTestConnector(t, store, "blocked-cancel", json.RawMessage(`{}`))
	if err := store.PutConnector(record); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_CHILD", "1")
	t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_STOP_READING", "1")
	supervisor := NewSupervisor(store, nil)
	if err := supervisor.Start(t.Context(), record.InstallationID); err != nil {
		t.Fatal(err)
	}
	supervisor.mu.RLock()
	child := supervisor.children[record.InstallationID]
	supervisor.mu.RUnlock()
	child.mu.Lock()
	for index := range 20000 {
		token := "attempt-" + strconv.Itoa(index)
		child.active[token] = protocol.JobRequest{JobID: "job-" + strconv.Itoa(index), AttemptToken: token}
	}
	child.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	started := time.Now()
	err = supervisor.Close(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("blocked cancellation returned after %s", elapsed)
	}
}

func TestConnectorDescendantsTerminateWithChild(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "instance"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record := stageSupervisorTestConnector(t, store, "descendant", json.RawMessage(`{}`))
	if err := store.PutConnector(record); err != nil {
		t.Fatal(err)
	}
	pidPath := filepath.Join(t.TempDir(), "descendant.pid")
	t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_CHILD", "1")
	t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_DESCENDANT_PATH", pidPath)
	supervisor := NewSupervisor(store, nil)
	if err := supervisor.Start(t.Context(), record.InstallationID); err != nil {
		t.Fatal(err)
	}
	pid := waitForTestPID(t, pidPath)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if err := supervisor.Close(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for processRunning(pid) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if processRunning(pid) {
		t.Fatalf("connector descendant %d remains running", pid)
	}
}

func stageSupervisorTestConnector(t *testing.T, store *Store, id string, settings json.RawMessage) ConnectorRecord {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	record, err := NewArtifactInstaller(store, nil).StageLocal(t.Context(), LocalArtifactInput{InstallationID: id, SourcePath: executable, DisplayName: "Supervisor helper", Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func waitForTestPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		body, err := os.ReadFile(path)
		if err == nil {
			pid, parseErr := strconv.Atoi(string(body))
			if parseErr == nil && pid > 0 {
				return pid
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("descendant PID was not written: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
