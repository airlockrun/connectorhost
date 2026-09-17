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
	supervisor.mu.RLock()
	retained := supervisor.children[record.InstallationID] == child
	supervisor.mu.RUnlock()
	if !retained {
		t.Fatal("failed stop discarded child before exit was confirmed")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := supervisor.Stop(context.Background(), record.InstallationID); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stop retry did not confirm process exit")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestActivateRejectsDuplicateBeforeLaunch(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	first := inventoryTestRecord(inventoryID)
	if err := store.PutConnector(first); err != nil {
		t.Fatal(err)
	}
	supervisor := NewSupervisor(store, nil)
	duplicate := inventoryTestRecord(otherInventoryID)
	err = supervisor.Activate(t.Context(), duplicate, func() error { t.Fatal("duplicate reached persistence"); return nil })
	if err == nil || !strings.Contains(err.Error(), "duplicate installations") {
		t.Fatalf("admission must precede executable lookup and launch: %v", err)
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

type drainingSink struct {
	event   chan struct{}
	release chan struct{}
	completionSink
}

func (s *drainingSink) ConnectorEvent(context.Context, string, string, protocol.JobEvent) error {
	close(s.event)
	<-s.release
	return nil
}

func TestParentExitCleansDescendantBeforeDrainingBufferedCompletion(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record := stageSupervisorTestConnector(t, store, "parent-exit", json.RawMessage(`{}`))
	if err := store.PutConnector(record); err != nil {
		t.Fatal(err)
	}
	pidPath := filepath.Join(t.TempDir(), "descendant.pid")
	t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_CHILD", "1")
	t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_DESCENDANT_PATH", pidPath)
	t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_EXIT_AFTER_JOB", "1")
	sink := &drainingSink{event: make(chan struct{}), release: make(chan struct{}), completionSink: completionSink{done: make(chan protocol.JobCompletion, 2)}}
	supervisor := NewSupervisor(store, sink)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := supervisor.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	defer func() {
		select {
		case <-sink.release:
		default:
			close(sink.release)
		}
	}()
	if err := supervisor.Start(t.Context(), record.InstallationID); err != nil {
		t.Fatal(err)
	}
	pid := waitForTestPID(t, pidPath)
	supervisor.mu.RLock()
	child := supervisor.children[record.InstallationID]
	supervisor.mu.RUnlock()
	if err := supervisor.Dispatch(record.InstallationID, protocol.JobRequest{JobID: "job", AttemptToken: "attempt", Input: json.RawMessage(`{}`), Deadline: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sink.event:
	case <-time.After(5 * time.Second):
		t.Fatal("child did not emit progress")
	}
	select {
	case <-child.processDone:
	case <-time.After(5 * time.Second):
		t.Fatal("parent exit waited for descendant stdout EOF")
	}
	deadline := time.Now().Add(5 * time.Second)
	for processRunning(pid) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if processRunning(pid) {
		t.Fatal("parent exit did not clean up descendant")
	}
	close(sink.release)
	select {
	case completion := <-sink.done:
		if completion.Status != "success" {
			t.Fatalf("buffered terminal frame lost: %+v", completion)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("buffered completion did not drain")
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		supervisor.mu.RLock()
		restarted := supervisor.children[record.InstallationID] != child
		supervisor.mu.RUnlock()
		if restarted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("parent exit did not recover connector")
		}
		time.Sleep(10 * time.Millisecond)
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
