package main

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	connectorhost "github.com/airlockrun/connectorhost"
)

type testNativeServiceManager struct {
	stateDirectory string
	status         nativeServiceStatus
	startCalls     int
}

func (*testNativeServiceManager) Install(context.Context) error   { return nil }
func (*testNativeServiceManager) Stop(context.Context) error      { return nil }
func (*testNativeServiceManager) Uninstall(context.Context) error { return nil }
func (m *testNativeServiceManager) StateDirectory() string        { return m.stateDirectory }
func (m *testNativeServiceManager) Status(context.Context) (nativeServiceStatus, error) {
	return m.status, nil
}
func (m *testNativeServiceManager) Start(context.Context) error {
	m.startCalls++
	return nil
}

func TestManagedEnrollmentDoesNotStartEnrolledService(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := connectorhost.OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetCredentials("https://airlock.example", "credential", "host-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	manager := &testNativeServiceManager{stateDirectory: root, status: nativeServiceStatus{State: serviceStopped}}
	err = enrollManagedService(t.Context(), manager, "https://airlock.example", connectorhost.AccessNone, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "already enrolled") {
		t.Fatalf("enrollment error = %v", err)
	}
	if manager.startCalls != 0 {
		t.Fatalf("start calls = %d", manager.startCalls)
	}
}
