package connectorhost

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

const managementOutcomeVersion = 2

type managementOutcome struct {
	Version          int                   `json:"version"`
	JobID            string                `json:"jobId"`
	AttemptToken     string                `json:"attemptToken"`
	Kind             protocol.HostWorkKind `json:"kind"`
	ConnectorID      string                `json:"connectorId,omitempty"`
	Status           string                `json:"status"`
	Output           json.RawMessage       `json:"output,omitempty"`
	Error            string                `json:"error,omitempty"`
	ProcessID        int                   `json:"processId,omitempty"`
	UpdatedAt        time.Time             `json:"updatedAt"`
	ConnectorExisted bool                  `json:"connectorExisted,omitempty"`
	ConnectorBefore  *ConnectorRecord      `json:"connectorBefore,omitempty"`
}

func (s *Store) loadManagementOutcome(jobID string) (managementOutcome, bool, error) {
	body, err := os.ReadFile(s.managementOutcomePath(jobID))
	if errors.Is(err, os.ErrNotExist) {
		return managementOutcome{}, false, nil
	}
	if err != nil {
		return managementOutcome{}, false, err
	}
	var outcome managementOutcome
	if err := strictJSON(body, &outcome); err != nil {
		return managementOutcome{}, false, err
	}
	if outcome.Version != managementOutcomeVersion || outcome.JobID != jobID || outcome.AttemptToken == "" || outcome.Kind == "" || outcome.ProcessID < 0 || outcome.UpdatedAt.IsZero() {
		return managementOutcome{}, false, errors.New("connectorhost: invalid management outcome journal")
	}
	switch outcome.Status {
	case "running", "success", "error", "canceled", "timeout":
	default:
		return managementOutcome{}, false, errors.New("connectorhost: invalid management outcome status")
	}
	if outcome.ConnectorExisted != (outcome.ConnectorBefore != nil) {
		return managementOutcome{}, false, errors.New("connectorhost: invalid management outcome connector snapshot")
	}
	if outcome.ConnectorBefore != nil {
		if outcome.ConnectorBefore.InstallationID != outcome.ConnectorID || validateConnectorRecord(*outcome.ConnectorBefore) != nil {
			return managementOutcome{}, false, errors.New("connectorhost: invalid management outcome connector snapshot")
		}
	}
	return outcome, true, nil
}

func (s *Store) managementOutcomes() ([]managementOutcome, error) {
	directory := filepath.Join(s.root, "management")
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	outcomes := make([]managementOutcome, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		var outcome managementOutcome
		if err := strictJSON(body, &outcome); err != nil {
			return nil, err
		}
		loaded, found, err := s.loadManagementOutcome(outcome.JobID)
		if err != nil || !found || s.managementOutcomePath(outcome.JobID) != filepath.Join(directory, entry.Name()) {
			return nil, errors.Join(errors.New("connectorhost: invalid management journal entry"), err)
		}
		outcomes = append(outcomes, loaded)
	}
	return outcomes, nil
}

func (s *Store) saveManagementOutcome(outcome managementOutcome) error {
	if outcome.JobID == "" || outcome.Kind == "" {
		return errors.New("connectorhost: management outcome identity is required")
	}
	outcome.Version = managementOutcomeVersion
	outcome.UpdatedAt = time.Now().UTC()
	body, err := json.MarshalIndent(outcome, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	directory := filepath.Join(s.root, "management")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	return atomicWrite(s.managementOutcomePath(outcome.JobID), body, 0o600)
}

func (s *Store) removeManagementOutcome(jobID string) error {
	err := os.Remove(s.managementOutcomePath(jobID))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *Store) managementOutcomePath(jobID string) string {
	digest := sha256.Sum256([]byte(jobID))
	return filepath.Join(s.root, "management", hex.EncodeToString(digest[:])+".json")
}
