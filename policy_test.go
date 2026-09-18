package connectorhost

import (
	"fmt"
	"testing"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

func TestRemoteManagementPolicyFailsClosed(t *testing.T) {
	tests := []struct {
		kind                  protocol.HostWorkKind
		full, manage, updates bool
	}{
		{protocol.HostWorkShell, true, false, false},
		{protocol.HostWorkConnectorInstall, true, true, false},
		{protocol.HostWorkConnectorUpdate, true, true, true},
		{protocol.HostWorkConnectorRollback, true, true, true},
		{protocol.HostWorkConnectorRemove, true, true, false},
		{protocol.HostWorkConnectorJob, false, false, false},
		{protocol.HostWorkConnectorCancel, false, false, false},
		{"unknown", false, false, false},
		{"", false, false, false},
	}
	for _, test := range tests {
		for _, existing := range []bool{false, true} {
			for mode, allowed := range map[AccessMode]bool{
				AccessFull: test.full, AccessManage: test.manage,
				AccessUpdates: existing && test.updates, AccessNone: false,
				"unknown": false, "": false, "update_only": false, "manage_connectors": false,
			} {
				t.Run(fmt.Sprintf("%s/%s/existing=%t", mode, test.kind, existing), func(t *testing.T) {
					if got := AllowsRemoteManagement(mode, test.kind, existing); got != allowed {
						t.Fatalf("allowed = %t, want %t", got, allowed)
					}
				})
			}
		}
	}
}

func TestParseAccessMode(t *testing.T) {
	for _, test := range []struct {
		value string
		want  AccessMode
	}{
		{"full", AccessFull},
		{"manage", AccessManage},
		{"updates", AccessUpdates},
		{"none", AccessNone},
		{"admin", ""}, {"", ""}, {"manage_connectors", ""}, {"update_only", ""},
		{"manage-connectors", ""}, {"Manage", ""}, {"Updates", ""}, {" manage ", ""},
	} {
		t.Run(test.value, func(t *testing.T) {
			got, err := ParseAccessMode(test.value)
			if got != test.want || (err != nil) != (test.want == "") {
				t.Fatalf("ParseAccessMode(%q) = %q, %v", test.value, got, err)
			}
		})
	}
}
