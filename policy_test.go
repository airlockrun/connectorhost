package connectorhost

import (
	"testing"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

func TestRemoteManagementPolicyFailsClosed(t *testing.T) {
	tests := []struct {
		mode              AccessMode
		kind              protocol.HostWorkKind
		existing, allowed bool
	}{
		{AccessFull, protocol.HostWorkShell, false, true},
		{AccessFull, protocol.HostWorkConnectorInstall, false, true},
		{AccessUpdateOnly, protocol.HostWorkConnectorUpdate, true, true},
		{AccessUpdateOnly, protocol.HostWorkConnectorRollback, true, true},
		{AccessUpdateOnly, protocol.HostWorkConnectorInstall, false, false},
		{AccessUpdateOnly, protocol.HostWorkShell, true, false},
		{AccessNone, protocol.HostWorkConnectorUpdate, true, false},
	}
	for _, test := range tests {
		if got := AllowsRemoteManagement(test.mode, test.kind, test.existing); got != test.allowed {
			t.Errorf("AllowsRemoteManagement(%q, %q, %t) = %t", test.mode, test.kind, test.existing, got)
		}
	}
}

func TestParseAccessModeRejectsUnknown(t *testing.T) {
	if _, err := ParseAccessMode("admin"); err == nil {
		t.Fatal("unknown access mode accepted")
	}
}
