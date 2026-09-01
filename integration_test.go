package connectorhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

func TestMain(main *testing.M) {
	if os.Getenv("AIRLOCK_CONNECTOR_HOST_TEST_DESCENDANT") == "1" {
		for {
			time.Sleep(time.Hour)
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "__airlock_shell" {
		os.Exit(RunShellHelper(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	if len(os.Args) == 2 && os.Args[1] == "manifest" {
		if path := os.Getenv("AIRLOCK_CONNECTOR_HOST_TEST_MANIFEST_DESCENDANT_PATH"); path != "" {
			command := exec.Command(os.Args[0])
			command.Env = append(os.Environ(), "AIRLOCK_CONNECTOR_HOST_TEST_DESCENDANT=1")
			command.Stdout, command.Stderr = os.Stdout, os.Stderr
			if command.Start() == nil {
				_ = os.WriteFile(path, []byte(strconv.Itoa(command.Process.Pid)), 0o600)
				_ = command.Process.Release()
			}
		}
		if os.Getenv("AIRLOCK_CONNECTOR_HOST_TEST_MANIFEST_OVERFLOW") == "1" {
			remaining := protocol.MaxManifestBytes + 1
			chunk := []byte(strings.Repeat("x", 32<<10))
			for remaining > 0 {
				if len(chunk) > remaining {
					chunk = chunk[:remaining]
				}
				written, err := os.Stdout.Write(chunk)
				if err != nil {
					break
				}
				remaining -= written
			}
		}
		_ = json.NewEncoder(os.Stdout).Encode(helperManifest())
		if os.Getenv("AIRLOCK_CONNECTOR_HOST_TEST_MANIFEST_HANG") == "1" {
			for {
				time.Sleep(time.Hour)
			}
		}
		os.Exit(0)
	}
	if os.Getenv("AIRLOCK_CONNECTOR_HOST_TEST_CHILD") == "1" {
		runHelperChild()
		os.Exit(0)
	}
	os.Exit(main.Run())
}

func TestInterruptedUpdateRestoresPreviousConnector(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer server.Close()
	store, err := OpenStore(filepath.Join(t.TempDir(), "instance"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	old, err := NewArtifactInstaller(store, server.Client()).Stage(context.Background(), protocol.ConnectorArtifactInput{InstallationID: "helper-1", URL: server.URL + "/connector", Filename: "helper", SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(body))}, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutConnector(old); err != nil {
		t.Fatal(err)
	}
	candidate := cloneRecord(old)
	candidate.ActiveDigest = strings.Repeat("c", 64)
	candidate.Manifest.ArtifactDigest = candidate.ActiveDigest
	candidate.PreviousDigest, candidate.PreviousFilename = old.ActiveDigest, old.Filename
	candidate.PreviousSettings = append(json.RawMessage(nil), old.Settings...)
	previousManifest := old.Manifest
	candidate.PreviousManifest = &previousManifest
	if err := store.PutConnector(candidate); err != nil {
		t.Fatal(err)
	}
	before := cloneRecord(old)
	if err := store.saveManagementOutcome(managementOutcome{JobID: "job-update", AttemptToken: "attempt-update", Kind: protocol.HostWorkConnectorUpdate, ConnectorID: old.InstallationID, Status: "running", ConnectorExisted: true, ConnectorBefore: &before}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_CHILD", "1")
	host := newTestHost(store, server.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := host.recoverInterruptedManagement(ctx); err != nil {
		t.Fatal(err)
	}
	restored, exists := store.Connector(old.InstallationID)
	if !exists || restored.ActiveDigest != old.ActiveDigest {
		t.Fatalf("restored connector = %+v, exists = %t", restored, exists)
	}
	outcome, found, err := store.loadManagementOutcome("job-update")
	if err != nil || !found || outcome.Status != "error" {
		t.Fatalf("recovered outcome = %+v, %t, %v", outcome, found, err)
	}
	stopCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := host.supervisor.Close(stopCtx); err != nil {
		t.Fatal(err)
	}
}

func TestInterruptedShellIsFinalized(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "instance"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.saveManagementOutcome(managementOutcome{JobID: "job-shell", AttemptToken: "attempt-shell", Kind: protocol.HostWorkShell, Status: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := newTestHost(store, http.DefaultClient).recoverInterruptedManagement(t.Context()); err != nil {
		t.Fatal(err)
	}
	outcome, found, err := store.loadManagementOutcome("job-shell")
	if err != nil || !found || outcome.Status != "error" {
		t.Fatalf("recovered outcome = %+v, %t, %v", outcome, found, err)
	}
}

func helperManifest() protocol.Manifest {
	executable, _ := os.Executable()
	body, _ := os.ReadFile(executable)
	digest := sha256.Sum256(body)
	target := runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOARCH == "arm" {
		target = runtime.GOOS + "-armv7"
	}
	manifest := protocol.Manifest{ProtocolMajor: protocol.Major, ProtocolMinor: protocol.Minor, Features: []string{"hosted-child-v1"}, Targets: []string{target}, ArtifactDigest: hex.EncodeToString(digest[:]), Interface: protocol.Interface{Kind: "helper", ContractID: "io.airlockrun.connectorhost_helper", Name: "Helper", Description: "Connector host test helper.", ArtifactVersion: "1"}}
	manifest.InterfaceHash, _ = protocol.InterfaceDigest(manifest.Interface)
	return manifest
}

func runHelperChild() {
	if os.Getenv("AIRLOCK_CONNECTOR_HOST_TEST_NO_STDIN") == "1" {
		for {
			time.Sleep(time.Hour)
		}
	}
	decoder, encoder := protocol.NewChildDecoder(os.Stdin), protocol.NewChildEncoder(os.Stdout)
	var envelope protocol.ChildEnvelope
	if decoder.Decode(&envelope) != nil || envelope.Initialize == nil {
		return
	}
	writeTestOrigins(os.Getenv("AIRLOCK_CONNECTOR_HOST_TEST_INITIALIZE_PATH"), envelope.Initialize.StorageOrigins)
	if path := os.Getenv("AIRLOCK_CONNECTOR_HOST_TEST_INITIALIZE_PID_PATH"); path != "" {
		_ = os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0o600)
	}
	if path := os.Getenv("AIRLOCK_CONNECTOR_HOST_TEST_DESCENDANT_PATH"); path != "" {
		command := exec.Command(os.Args[0])
		command.Env = append(os.Environ(), "AIRLOCK_CONNECTOR_HOST_TEST_DESCENDANT=1")
		if command.Start() == nil {
			_ = os.WriteFile(path, []byte(strconv.Itoa(command.Process.Pid)), 0o600)
			_ = command.Process.Release()
		}
	}
	ready := protocol.ChildReady{ProtocolVersion: protocol.HostProtocolVersion, Manifest: helperManifest(), Readiness: protocol.ReadinessReady}
	if os.Getenv("AIRLOCK_CONNECTOR_HOST_TEST_READINESS") == "fail" {
		ready.Readiness = protocol.ReadinessUnhealthy
		ready.Error = "forced readiness failure"
	}
	if os.Getenv("AIRLOCK_CONNECTOR_HOST_TEST_REJECT_INITIALIZE_ORIGINS") == "1" && len(envelope.Initialize.StorageOrigins) != 0 {
		ready.Readiness = protocol.ReadinessUnhealthy
		ready.Error = "forced initialization rejection"
	}
	if encoder.Encode(protocol.ChildEnvelope{Type: protocol.ChildMessageReady, Ready: &ready}) != nil {
		return
	}
	if path := os.Getenv("AIRLOCK_CONNECTOR_HOST_TEST_SPONTANEOUS_READY_PATH"); path != "" {
		go func() {
			for {
				if _, err := os.Stat(path); err == nil {
					if encoder.Encode(protocol.ChildEnvelope{Type: protocol.ChildMessageReady, Ready: &ready}) == nil {
						_ = os.WriteFile(path+".sent", []byte("sent"), 0o600)
					}
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}
	if os.Getenv("AIRLOCK_CONNECTOR_HOST_TEST_STOP_READING") == "1" {
		for {
			time.Sleep(time.Hour)
		}
	}
	for decoder.Decode(&envelope) == nil {
		if envelope.Settings != nil {
			if os.Getenv("AIRLOCK_CONNECTOR_HOST_TEST_REJECT_SETTINGS") == "1" {
				rejected := ready
				rejected.Readiness = protocol.ReadinessUnhealthy
				rejected.Error = "forced settings rejection"
				_ = encoder.Encode(protocol.ChildEnvelope{Type: protocol.ChildMessageReady, Ready: &rejected})
				continue
			}
			writeTestOrigins(os.Getenv("AIRLOCK_CONNECTOR_HOST_TEST_SETTINGS_PATH"), envelope.Settings.StorageOrigins)
			_ = encoder.Encode(protocol.ChildEnvelope{Type: protocol.ChildMessageReady, Ready: &ready})
		}
		if envelope.Job != nil {
			if os.Getenv("AIRLOCK_CONNECTOR_HOST_TEST_BLOCK_JOBS") == "1" {
				continue
			}
			completion := protocol.JobCompletion{AttemptToken: envelope.Job.AttemptToken, Status: "success", Output: json.RawMessage(`{}`)}
			_ = encoder.Encode(protocol.ChildEnvelope{Type: protocol.ChildMessageCompletion, Completion: &completion})
		}
	}
}

func writeTestOrigins(path string, origins []string) {
	if path == "" {
		return
	}
	body, _ := json.Marshal(origins)
	_ = os.WriteFile(path, body, 0o600)
}

func TestArtifactStagingAndChildSupervision(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer server.Close()
	filename := "helper"
	if runtime.GOOS == "windows" {
		filename += ".exe"
	}
	store, err := OpenStore(filepath.Join(t.TempDir(), "instance"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	installer := NewArtifactInstaller(store, server.Client())
	record, err := installer.Stage(context.Background(), protocol.ConnectorArtifactInput{InstallationID: "helper-1", URL: server.URL + "/connector", Filename: filename, SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(body))}, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutConnector(record); err != nil {
		t.Fatal(err)
	}
	sink := &completionSink{done: make(chan protocol.JobCompletion, 1)}
	supervisor := NewSupervisor(store, sink)
	t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_CHILD", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := supervisor.Start(ctx, record.InstallationID); err != nil {
		t.Fatal(err)
	}
	job := protocol.JobRequest{JobID: "job-1", AttemptToken: "attempt-1", Kind: protocol.JobKindCommand, Input: json.RawMessage(`{}`), Deadline: time.Now().Add(time.Minute)}
	if err := supervisor.Dispatch(record.InstallationID, job); err != nil {
		t.Fatal(err)
	}
	select {
	case completion := <-sink.done:
		if completion.Status != "success" {
			t.Fatalf("completion = %+v", completion)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if statuses := supervisor.Statuses(); len(statuses) != 1 || statuses[0].Readiness != protocol.ReadinessReady {
		t.Fatalf("statuses = %+v", statuses)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	if err := supervisor.Close(stopCtx); err != nil {
		t.Fatal(err)
	}
}

type completionSink struct{ done chan protocol.JobCompletion }

func (*completionSink) ConnectorEvent(context.Context, string, string, protocol.JobEvent) error {
	return nil
}
func (s *completionSink) ConnectorCompletion(_ context.Context, _, _ string, completion protocol.JobCompletion) error {
	s.done <- completion
	return nil
}
