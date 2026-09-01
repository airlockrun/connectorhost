package connectorhost

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalControlUploadsConnectorArtifact(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "instance")
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host := NewHost(store, nil)
	server, err := NewLocalControlServer(host, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(ctx) }()
	t.Setenv("AIRLOCK_CONNECTOR_HOST_TEST_CHILD", "1")
	client, err := NewLocalControlClient(root)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.InstallFile(t.Context(), LocalInstallRequest{
		InstallationID: "11111111-1111-4111-8111-111111111111",
		SourcePath:     executable,
		DisplayName:    "Uploaded connector",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.InstallationID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("installation ID = %q", response.InstallationID)
	}
	record, exists := store.Connector(response.InstallationID)
	if !exists || record.Filename != filepath.Base(executable) {
		t.Fatalf("uploaded record = %+v, exists = %t", record, exists)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := host.Close(stopCtx); err != nil {
		t.Fatal(err)
	}
	stopCancel()
	cancel()
	if err := <-serveResult; err != nil {
		t.Fatal(err)
	}
}
