package connectorhost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

type LocalInstallRequest struct {
	InstallationID string          `json:"installationId,omitempty"`
	SourcePath     string          `json:"sourcePath"`
	DisplayName    string          `json:"displayName,omitempty"`
	ExpectedSHA256 string          `json:"expectedSha256,omitempty"`
	ArtifactSize   int64           `json:"artifactSize,omitempty"`
	Settings       json.RawMessage `json:"settings,omitempty"`
}

type LocalUpdateRequest struct {
	InstallationID string          `json:"installationId"`
	SourcePath     string          `json:"sourcePath"`
	ExpectedSHA256 string          `json:"expectedSha256,omitempty"`
	ArtifactSize   int64           `json:"artifactSize,omitempty"`
	Settings       json.RawMessage `json:"settings,omitempty"`
}

type LocalConnectorRequest struct {
	InstallationID string `json:"installationId"`
}

type LocalAccessRequest struct {
	Mode AccessMode `json:"mode"`
}

type LocalEnrollRequest struct {
	AirlockURL string `json:"airlockUrl"`
}

type LocalEnrollmentEvent struct {
	Type            string    `json:"type"`
	VerificationURL string    `json:"verificationUrl,omitempty"`
	UserCode        string    `json:"userCode,omitempty"`
	ExpiresAt       time.Time `json:"expiresAt,omitempty"`
	Error           string    `json:"error,omitempty"`
}

const (
	LocalEnrollmentVerification = "verification"
	LocalEnrollmentComplete     = "complete"
	LocalEnrollmentError        = "error"
)

type LocalInstallResponse struct {
	InstallationID string `json:"installationId"`
}

type LocalConnectorStatus struct {
	InstallationID  string                           `json:"installationId"`
	DisplayName     string                           `json:"displayName"`
	ArtifactDigest  string                           `json:"artifactDigest"`
	ArtifactVersion string                           `json:"artifactVersion"`
	Readiness       protocol.Readiness               `json:"readiness"`
	Error           string                           `json:"error,omitempty"`
	HasRollback     bool                             `json:"hasRollback"`
	InstalledAt     time.Time                        `json:"installedAt"`
	Manifest        protocol.HostedConnectorManifest `json:"manifest"`
}

func (h *Host) LocalEnroll(ctx context.Context, baseURL string, prompt func(EnrollmentPrompt) error) error {
	if !h.enrollmentMu.TryLock() {
		return errors.New("connectorhost: enrollment is already in progress")
	}
	defer h.enrollmentMu.Unlock()
	airlockURL, credential := h.store.Credentials()
	if airlockURL != "" || credential != "" {
		return errors.New("connectorhost: host is already enrolled")
	}
	if err := EnrollWithPrompt(ctx, h.store, baseURL, h.httpClient, prompt); err != nil {
		return err
	}
	h.signalCredentialsReady()
	return nil
}

func (h *Host) LocalInstall(ctx context.Context, request LocalInstallRequest) (LocalInstallResponse, error) {
	if request.InstallationID != "" {
		if err := validateInventoryInstallationID(request.InstallationID); err != nil {
			return LocalInstallResponse{}, err
		}
		h.managementMu.Lock()
		defer h.managementMu.Unlock()
		if _, exists := h.store.Connector(request.InstallationID); exists {
			return LocalInstallResponse{InstallationID: request.InstallationID}, nil
		}
		_, err := h.installLocal(ctx, LocalArtifactInput{
			InstallationID: request.InstallationID,
			SourcePath:     request.SourcePath,
			DisplayName:    request.DisplayName,
			ExpectedSHA256: request.ExpectedSHA256,
			Settings:       request.Settings,
		}, false)
		if err != nil {
			return LocalInstallResponse{}, err
		}
		return LocalInstallResponse{InstallationID: request.InstallationID}, nil
	}
	for attempts := 0; attempts < 4; attempts++ {
		id, err := NewInstallationID()
		if err != nil {
			return LocalInstallResponse{}, err
		}
		if _, exists := h.store.Connector(id); exists {
			continue
		}
		return h.localInstallWithID(ctx, request, id)
	}
	return LocalInstallResponse{}, errors.New("connectorhost: could not allocate a unique installation ID")
}

func (h *Host) localInstallWithID(ctx context.Context, request LocalInstallRequest, id string) (LocalInstallResponse, error) {
	_, err := h.InstallLocal(ctx, LocalArtifactInput{
		InstallationID: id,
		SourcePath:     request.SourcePath,
		DisplayName:    request.DisplayName,
		ExpectedSHA256: request.ExpectedSHA256,
		Settings:       request.Settings,
	}, false)
	if err != nil {
		return LocalInstallResponse{}, err
	}
	return LocalInstallResponse{InstallationID: id}, nil
}

func (h *Host) LocalUpdate(ctx context.Context, request LocalUpdateRequest) error {
	_, err := h.InstallLocal(ctx, LocalArtifactInput{
		InstallationID: request.InstallationID,
		SourcePath:     request.SourcePath,
		ExpectedSHA256: request.ExpectedSHA256,
		Settings:       request.Settings,
	}, true)
	return err
}

func (h *Host) LocalStatuses(id string) ([]LocalConnectorStatus, error) {
	h.managementMu.Lock()
	defer h.managementMu.Unlock()
	if id != "" {
		if err := validateInstallationID(id); err != nil {
			return nil, err
		}
	}
	statuses := make(map[string]protocol.HostedConnectorStatus)
	for _, status := range h.supervisor.Statuses() {
		statuses[status.InstallationID] = status
	}
	result := make([]LocalConnectorStatus, 0, len(statuses))
	for _, record := range h.store.Connectors() {
		if id != "" && record.InstallationID != id {
			continue
		}
		status := statuses[record.InstallationID]
		name := record.DisplayName
		if name == "" {
			name = record.Manifest.Interface.Name
		}
		result = append(result, LocalConnectorStatus{
			InstallationID:  record.InstallationID,
			DisplayName:     name,
			ArtifactDigest:  record.ActiveDigest,
			ArtifactVersion: record.Manifest.Interface.ArtifactVersion,
			Readiness:       status.Readiness,
			Error:           status.Error,
			HasRollback:     record.PreviousDigest != "",
			InstalledAt:     record.InstalledAt,
			Manifest:        protocol.SummarizeManifest(record.Manifest),
		})
	}
	if id != "" && len(result) == 0 {
		return nil, fmt.Errorf("connectorhost: connector %q is not installed", id)
	}
	return result, nil
}

func NewInstallationID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}
