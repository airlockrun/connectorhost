package connectorhost

import (
	"errors"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

type AccessMode = protocol.RemoteAccessMode

const (
	AccessFull    = protocol.RemoteAccessFull
	AccessManage  = protocol.RemoteAccessManage
	AccessUpdates = protocol.RemoteAccessUpdates
	AccessNone    = protocol.RemoteAccessNone
)

func ParseAccessMode(value string) (AccessMode, error) {
	mode := AccessMode(value)
	switch mode {
	case AccessFull, AccessManage, AccessUpdates, AccessNone:
		return mode, nil
	default:
		return "", errors.New("connectorhost: access mode must be full, manage, updates, or none")
	}
}

func AllowsRemoteManagement(mode AccessMode, kind protocol.HostWorkKind, existing bool) bool {
	switch mode {
	case AccessFull:
		return kind == protocol.HostWorkShell || kind == protocol.HostWorkConnectorInstall || kind == protocol.HostWorkConnectorUpdate || kind == protocol.HostWorkConnectorRemove || kind == protocol.HostWorkConnectorRollback
	case AccessManage:
		return kind == protocol.HostWorkConnectorInstall || kind == protocol.HostWorkConnectorUpdate || kind == protocol.HostWorkConnectorRemove || kind == protocol.HostWorkConnectorRollback
	case AccessUpdates:
		return existing && (kind == protocol.HostWorkConnectorUpdate || kind == protocol.HostWorkConnectorRollback)
	default:
		return false
	}
}
