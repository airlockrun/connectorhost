//go:build !windows

package connectorhost

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

func TestExecuteShellBoundsOutputAndReplacesEnvironment(t *testing.T) {
	output, err := ExecuteShell(context.Background(), protocol.ShellInput{Command: "/bin/sh", Arguments: []string{"-c", `printf %s "$AIRLOCK_TEST_VALUE"`}, Environment: map[string]string{"AIRLOCK_TEST_VALUE": "local"}}, shellStarted)
	if err != nil {
		t.Fatal(err)
	}
	if string(output.Stdout) != "local" || output.ExitCode != 0 {
		t.Fatalf("output = %+v", output)
	}
	if _, err := ExecuteShell(context.Background(), protocol.ShellInput{Command: "/bin/sh", Arguments: []string{"-c", "printf 12345"}, MaxOutputBytes: 4}, shellStarted); err == nil {
		t.Fatal("oversized shell output accepted")
	}
	if _, err := ExecuteShell(context.Background(), protocol.ShellInput{Command: "/bin/sh", Arguments: []string{"-c", "printf 123; printf 456 >&2"}, MaxOutputBytes: 5}, shellStarted); err == nil {
		t.Fatal("oversized aggregate shell output accepted")
	}
}

func TestExecuteShellHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := ExecuteShell(ctx, protocol.ShellInput{Command: "/bin/sh", Arguments: []string{"-c", "sleep 5"}}, shellStarted)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
}

func shellStarted(int) error { return nil }
