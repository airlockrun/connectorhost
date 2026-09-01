package connectorhost

import (
	"fmt"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

type AccessMode = protocol.RemoteAccessMode

const (
	AccessFull       = protocol.RemoteAccessFull
	AccessUpdateOnly = protocol.RemoteAccessUpdateOnly
	AccessNone       = protocol.RemoteAccessNone
)

func ParseAccessMode(value string) (AccessMode, error) {
	mode := AccessMode(value)
	switch mode {
	case AccessFull, AccessUpdateOnly, AccessNone:
		return mode, nil
	default:
		return "", fmt.Errorf("connectorhost: access mode must be full, update_only, or none")
	}
}

func AllowsRemoteManagement(mode AccessMode, kind protocol.HostWorkKind, existing bool) bool {
	switch mode {
	case AccessFull:
		return kind == protocol.HostWorkShell || kind == protocol.HostWorkConnectorInstall || kind == protocol.HostWorkConnectorUpdate || kind == protocol.HostWorkConnectorRemove || kind == protocol.HostWorkConnectorRollback
	case AccessUpdateOnly:
		return existing && (kind == protocol.HostWorkConnectorUpdate || kind == protocol.HostWorkConnectorRollback)
	default:
		return false
	}
}
