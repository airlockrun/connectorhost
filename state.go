package connectorhost

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

const stateVersion = 2

var ErrStateLocked = errors.New("connectorhost: state directory is locked")

var installationIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type ConnectorRecord struct {
	InstallationID         string             `json:"installationId"`
	DisplayName            string             `json:"displayName,omitempty"`
	ActiveDigest           string             `json:"activeDigest"`
	PreviousDigest         string             `json:"previousDigest,omitempty"`
	Filename               string             `json:"filename"`
	PreviousFilename       string             `json:"previousFilename,omitempty"`
	Settings               json.RawMessage    `json:"settings"`
	PreviousSettings       json.RawMessage    `json:"previousSettings,omitempty"`
	StorageOrigins         []string           `json:"storageOrigins,omitempty"`
	PreviousStorageOrigins []string           `json:"previousStorageOrigins,omitempty"`
	Manifest               protocol.Manifest  `json:"manifest"`
	PreviousManifest       *protocol.Manifest `json:"previousManifest,omitempty"`
	InstalledAt            time.Time          `json:"installedAt"`
	InventoryAcknowledged  bool               `json:"inventoryAcknowledged,omitempty"`
}

type persistedState struct {
	Version                   int                                                       `json:"version"`
	HostID                    string                                                    `json:"hostId,omitempty"`
	AirlockURL                string                                                    `json:"airlockUrl,omitempty"`
	Credential                string                                                    `json:"credential,omitempty"`
	AccessMode                AccessMode                                                `json:"accessMode"`
	MutationRevision          uint64                                                    `json:"mutationRevision,omitempty"`
	Connectors                map[string]*ConnectorRecord                               `json:"connectors"`
	PendingInventoryMutations map[string]protocol.HostConnectorInventoryMutationRequest `json:"pendingInventoryMutations,omitempty"`
}

type Store struct {
	root  string
	lock  processLock
	mu    sync.RWMutex
	state persistedState
}

func OpenStore(root string) (*Store, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("connectorhost: state directory must be absolute")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, err
	}
	if err := secureDirectory(root); err != nil {
		return nil, err
	}
	lock, err := acquireProcessLock(filepath.Join(root, ".lock"))
	if err != nil {
		return nil, fmt.Errorf("connectorhost: lock state directory: %w", err)
	}
	store := &Store{root: root, lock: lock}
	if err := store.load(); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) load() error {
	body, err := os.ReadFile(filepath.Join(s.root, "host.json"))
	if errors.Is(err, os.ErrNotExist) {
		s.state = persistedState{Version: stateVersion, AccessMode: AccessFull, Connectors: make(map[string]*ConnectorRecord), PendingInventoryMutations: make(map[string]protocol.HostConnectorInventoryMutationRequest)}
		return s.saveLocked()
	}
	if err != nil {
		return err
	}
	if err := strictJSON(body, &s.state); err != nil {
		return fmt.Errorf("connectorhost: decode state: %w", err)
	}
	migrated := false
	if s.state.Version == 1 && s.state.Connectors != nil {
		for _, record := range s.state.Connectors {
			if record != nil {
				record.InventoryAcknowledged = true
			}
		}
		s.state.Version = stateVersion
		s.state.PendingInventoryMutations = make(map[string]protocol.HostConnectorInventoryMutationRequest)
		migrated = true
	}
	if s.state.Version != stateVersion || s.state.Connectors == nil {
		return errors.New("connectorhost: unsupported or invalid state")
	}
	if s.state.PendingInventoryMutations == nil {
		s.state.PendingInventoryMutations = make(map[string]protocol.HostConnectorInventoryMutationRequest)
	}
	if len(s.state.PendingInventoryMutations) > protocol.MaxHostedConnectors {
		return errors.New("connectorhost: pending inventory mutation limit exceeded")
	}
	if _, err := ParseAccessMode(string(s.state.AccessMode)); err != nil {
		return err
	}
	for id, record := range s.state.Connectors {
		if record == nil || id != record.InstallationID {
			return errors.New("connectorhost: connector state key does not match its installation ID")
		}
		if err := validateConnectorRecord(*record); err != nil {
			return err
		}
	}
	for id, mutation := range s.state.PendingInventoryMutations {
		if id != mutation.InstallationID || mutation.Revision > s.state.MutationRevision {
			return errors.New("connectorhost: invalid pending inventory mutation identity or revision")
		}
		if err := protocol.ValidateHostConnectorInventoryMutationRequest(mutation); err != nil {
			return fmt.Errorf("connectorhost: invalid pending inventory mutation: %w", err)
		}
		_, exists := s.state.Connectors[id]
		if (mutation.Kind == protocol.HostConnectorMutationUpsert) != exists {
			return errors.New("connectorhost: pending inventory mutation does not match connector state")
		}
		if exists && !inventoryMutationsEqual(mutation, inventoryUpsertMutation(*s.state.Connectors[id], mutation.Revision)) {
			return errors.New("connectorhost: pending inventory upsert does not match connector state")
		}
	}
	if migrated {
		return s.saveLocked()
	}
	return nil
}

func (s *Store) Close() error { return s.lock.Close() }
func (s *Store) Root() string { return s.root }

func (s *Store) AccessMode() AccessMode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.AccessMode
}

func (s *Store) SetAccessMode(mode AccessMode) error {
	if _, err := ParseAccessMode(string(mode)); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := s.state
	candidate.AccessMode = mode
	if err := s.saveStateLocked(candidate); err != nil {
		return err
	}
	s.state = candidate
	return nil
}

func (s *Store) Credentials() (string, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.AirlockURL, s.state.Credential
}

func (s *Store) SetCredentials(baseURL, credential, hostID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := s.state
	candidate.AirlockURL, candidate.Credential, candidate.HostID = baseURL, credential, hostID
	if err := s.saveStateLocked(candidate); err != nil {
		return err
	}
	s.state = candidate
	return nil
}

func (s *Store) HostID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.HostID
}

func (s *Store) Connector(id string) (ConnectorRecord, bool) {
	if validateInstallationID(id) != nil {
		return ConnectorRecord{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.state.Connectors[id]
	if !ok {
		return ConnectorRecord{}, false
	}
	return cloneRecord(*record), true
}

func (s *Store) Connectors() []ConnectorRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]ConnectorRecord, 0, len(s.state.Connectors))
	for _, record := range s.state.Connectors {
		result = append(result, cloneRecord(*record))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].InstallationID < result[j].InstallationID })
	return result
}

func (s *Store) PutConnector(record ConnectorRecord) error {
	if err := validateConnectorRecord(record); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := s.state
	candidate.Connectors = cloneConnectors(s.state.Connectors)
	copy := cloneRecord(record)
	candidate.Connectors[record.InstallationID] = &copy
	if err := s.saveStateLocked(candidate); err != nil {
		return err
	}
	s.state = candidate
	return nil
}

func (s *Store) PutRemoteConnector(record ConnectorRecord) error {
	record.InventoryAcknowledged = true
	if err := validateConnectorRecord(record); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := s.state
	candidate.Connectors = cloneConnectors(s.state.Connectors)
	candidate.PendingInventoryMutations = cloneInventoryMutations(s.state.PendingInventoryMutations)
	copy := cloneRecord(record)
	candidate.Connectors[record.InstallationID] = &copy
	delete(candidate.PendingInventoryMutations, record.InstallationID)
	if err := s.saveStateLocked(candidate); err != nil {
		return err
	}
	s.state = candidate
	return nil
}

func (s *Store) PutLocalConnector(record ConnectorRecord) error {
	if err := validateConnectorRecord(record); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, exists := s.state.Connectors[record.InstallationID]; exists {
		record.InventoryAcknowledged = current.InventoryAcknowledged
		if record.PreviousManifest != nil && current.ActiveDigest == record.PreviousDigest && manifestsEqual(current.Manifest, *record.PreviousManifest) {
			record.PreviousStorageOrigins = append([]string(nil), current.StorageOrigins...)
		}
	}
	if _, pending := s.state.PendingInventoryMutations[record.InstallationID]; !pending && len(s.state.PendingInventoryMutations) >= protocol.MaxHostedConnectors {
		return errors.New("connectorhost: pending inventory mutation limit reached")
	}
	revision, err := nextMutationRevision(s.state.MutationRevision)
	if err != nil {
		return err
	}
	mutation := inventoryUpsertMutation(record, revision)
	if err := protocol.ValidateHostConnectorInventoryMutationRequest(mutation); err != nil {
		return err
	}
	candidate := s.state
	candidate.MutationRevision = revision
	candidate.Connectors = cloneConnectors(s.state.Connectors)
	candidate.PendingInventoryMutations = cloneInventoryMutations(s.state.PendingInventoryMutations)
	copy := cloneRecord(record)
	candidate.Connectors[record.InstallationID] = &copy
	candidate.PendingInventoryMutations[record.InstallationID] = mutation
	if err := s.saveStateLocked(candidate); err != nil {
		return err
	}
	s.state = candidate
	return nil
}

func (s *Store) RemoveConnector(id string) error {
	if err := validateInstallationID(id); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.state.Connectors[id]; !exists {
		return fmt.Errorf("connectorhost: connector %q is not installed", id)
	}
	candidate := s.state
	candidate.Connectors = cloneConnectors(s.state.Connectors)
	delete(candidate.Connectors, id)
	if err := s.saveStateLocked(candidate); err != nil {
		return err
	}
	s.state = candidate
	return nil
}

func (s *Store) RemoveRemoteConnector(id string) error {
	if err := validateInstallationID(id); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.state.Connectors[id]; !exists {
		return fmt.Errorf("connectorhost: connector %q is not installed", id)
	}
	candidate := s.state
	candidate.Connectors = cloneConnectors(s.state.Connectors)
	candidate.PendingInventoryMutations = cloneInventoryMutations(s.state.PendingInventoryMutations)
	delete(candidate.Connectors, id)
	delete(candidate.PendingInventoryMutations, id)
	if err := s.saveStateLocked(candidate); err != nil {
		return err
	}
	s.state = candidate
	return nil
}

func (s *Store) RemoveLocalConnector(id string) error {
	if err := validateInstallationID(id); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.state.Connectors[id]; !exists {
		return fmt.Errorf("connectorhost: connector %q is not installed", id)
	}
	if _, pending := s.state.PendingInventoryMutations[id]; !pending && len(s.state.PendingInventoryMutations) >= protocol.MaxHostedConnectors {
		return errors.New("connectorhost: pending inventory mutation limit reached")
	}
	revision, err := nextMutationRevision(s.state.MutationRevision)
	if err != nil {
		return err
	}
	mutation := protocol.HostConnectorInventoryMutationRequest{InstallationID: id, Revision: revision, Kind: protocol.HostConnectorMutationRemove}
	if err := protocol.ValidateHostConnectorInventoryMutationRequest(mutation); err != nil {
		return err
	}
	candidate := s.state
	candidate.MutationRevision = revision
	candidate.Connectors = cloneConnectors(s.state.Connectors)
	candidate.PendingInventoryMutations = cloneInventoryMutations(s.state.PendingInventoryMutations)
	delete(candidate.Connectors, id)
	candidate.PendingInventoryMutations[id] = mutation
	if err := s.saveStateLocked(candidate); err != nil {
		return err
	}
	s.state = candidate
	return nil
}

func (s *Store) CanEnqueueInventoryMutation(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, pending := s.state.PendingInventoryMutations[id]
	return pending || len(s.state.PendingInventoryMutations) < protocol.MaxHostedConnectors
}

func (s *Store) PendingInventoryMutations() []protocol.HostConnectorInventoryMutationRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]protocol.HostConnectorInventoryMutationRequest, 0, len(s.state.PendingInventoryMutations))
	for _, mutation := range s.state.PendingInventoryMutations {
		result = append(result, cloneInventoryMutation(mutation))
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Revision == result[j].Revision {
			return result[i].InstallationID < result[j].InstallationID
		}
		return result[i].Revision < result[j].Revision
	})
	return result
}

func (s *Store) AcknowledgeInventoryMutation(request protocol.HostConnectorInventoryMutationRequest, response protocol.HostConnectorInventoryMutationResponse) (ConnectorRecord, bool, error) {
	if err := protocol.ValidateHostConnectorInventoryMutationResponse(response); err != nil {
		return ConnectorRecord{}, false, err
	}
	if response.InstallationID != request.InstallationID || response.AcknowledgedRevision != request.Revision {
		return ConnectorRecord{}, false, errors.New("connectorhost: inventory mutation response does not match its request")
	}
	if request.Kind == protocol.HostConnectorMutationRemove && len(response.StorageOrigins) != 0 {
		return ConnectorRecord{}, false, errors.New("connectorhost: inventory removal acknowledgement includes storage origins")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, exists := s.state.PendingInventoryMutations[request.InstallationID]
	if !exists || pending.Revision != request.Revision {
		return ConnectorRecord{}, false, nil
	}
	if !inventoryMutationsEqual(pending, request) {
		return ConnectorRecord{}, false, errors.New("connectorhost: pending inventory mutation changed without a new revision")
	}
	candidate := s.state
	candidate.PendingInventoryMutations = cloneInventoryMutations(s.state.PendingInventoryMutations)
	delete(candidate.PendingInventoryMutations, request.InstallationID)
	var acknowledged ConnectorRecord
	if request.Kind == protocol.HostConnectorMutationUpsert {
		record, found := s.state.Connectors[request.InstallationID]
		if !found {
			return ConnectorRecord{}, false, errors.New("connectorhost: acknowledged inventory upsert has no live connector")
		}
		candidate.Connectors = cloneConnectors(s.state.Connectors)
		acknowledged = cloneRecord(*record)
		acknowledged.InventoryAcknowledged = true
		acknowledged.StorageOrigins = append([]string(nil), response.StorageOrigins...)
		candidate.Connectors[request.InstallationID] = &acknowledged
	}
	if err := s.saveStateLocked(candidate); err != nil {
		return ConnectorRecord{}, false, err
	}
	s.state = candidate
	return cloneRecord(acknowledged), true, nil
}

func (s *Store) Executable(record ConnectorRecord) string {
	return filepath.Join(s.root, "connectors", record.InstallationID, "artifacts", record.ActiveDigest, record.Filename)
}

func (s *Store) ChildStateDirectory(id string) string {
	return filepath.Join(s.root, "connectors", id, "state")
}

func (s *Store) saveLocked() error {
	return s.saveStateLocked(s.state)
}

func (s *Store) rewriteCurrentState() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveStateLocked(s.state)
}

func (s *Store) saveStateLocked(state persistedState) error {
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return atomicWrite(filepath.Join(s.root, "host.json"), body, 0o600)
}

func cloneConnectors(connectors map[string]*ConnectorRecord) map[string]*ConnectorRecord {
	cloned := make(map[string]*ConnectorRecord, len(connectors))
	for id, record := range connectors {
		cloned[id] = record
	}
	return cloned
}

func cloneInventoryMutations(mutations map[string]protocol.HostConnectorInventoryMutationRequest) map[string]protocol.HostConnectorInventoryMutationRequest {
	cloned := make(map[string]protocol.HostConnectorInventoryMutationRequest, len(mutations))
	for id, mutation := range mutations {
		cloned[id] = mutation
	}
	return cloned
}

func cloneInventoryMutation(mutation protocol.HostConnectorInventoryMutationRequest) protocol.HostConnectorInventoryMutationRequest {
	body, err := json.Marshal(mutation)
	if err != nil {
		panic("connectorhost: clone validated inventory mutation: " + err.Error())
	}
	var copy protocol.HostConnectorInventoryMutationRequest
	if err := json.Unmarshal(body, &copy); err != nil {
		panic("connectorhost: clone validated inventory mutation: " + err.Error())
	}
	return copy
}

func inventoryMutationsEqual(left, right protocol.HostConnectorInventoryMutationRequest) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}

func inventoryUpsertMutation(record ConnectorRecord, revision uint64) protocol.HostConnectorInventoryMutationRequest {
	active := &protocol.ObservedConnectorArtifact{Manifest: record.Manifest, MeasuredDigest: record.ActiveDigest}
	mutation := protocol.HostConnectorInventoryMutationRequest{InstallationID: record.InstallationID, Revision: revision, Kind: protocol.HostConnectorMutationUpsert, DisplayName: record.DisplayName, Active: active}
	if record.PreviousManifest != nil {
		mutation.Rollback = &protocol.ObservedConnectorArtifact{Manifest: *record.PreviousManifest, MeasuredDigest: record.PreviousDigest}
	}
	return cloneInventoryMutation(mutation)
}

func nextMutationRevision(current uint64) (uint64, error) {
	if current == ^uint64(0) {
		return 0, errors.New("connectorhost: inventory mutation revision exhausted")
	}
	return current + 1, nil
}

func cloneRecord(record ConnectorRecord) ConnectorRecord {
	body, err := json.Marshal(record)
	if err != nil {
		panic("connectorhost: clone validated connector record: " + err.Error())
	}
	var copy ConnectorRecord
	if err := json.Unmarshal(body, &copy); err != nil {
		panic("connectorhost: clone validated connector record: " + err.Error())
	}
	return copy
}

func validateInstallationID(id string) error {
	if !installationIDPattern.MatchString(id) || id == "." || id == ".." {
		return errors.New("connectorhost: installation ID must be a path-safe identifier")
	}
	return nil
}

func validateInventoryInstallationID(id string) error {
	mutation := protocol.HostConnectorInventoryMutationRequest{InstallationID: id, Revision: 1, Kind: protocol.HostConnectorMutationRemove}
	return protocol.ValidateHostConnectorInventoryMutationRequest(mutation)
}

func validateConnectorRecord(record ConnectorRecord) error {
	if err := validateInstallationID(record.InstallationID); err != nil {
		return err
	}
	if err := validateDisplayName(record.DisplayName); err != nil {
		return err
	}
	if strings.TrimSpace(record.DisplayName) == "" {
		return errors.New("connectorhost: connector display name is required")
	}
	if err := validateArtifactFilename(record.Filename); err != nil {
		return err
	}
	if err := protocol.ValidateArtifactDigest(record.ActiveDigest); err != nil {
		return err
	}
	if len(record.Settings) == 0 || len(record.Settings) > protocol.MaxJobPayloadBytes || !json.Valid(record.Settings) {
		return errors.New("connectorhost: connector settings must be bounded valid JSON")
	}
	if err := validateHostStorageOrigins(record.StorageOrigins); err != nil {
		return err
	}
	if err := validateHostStorageOrigins(record.PreviousStorageOrigins); err != nil {
		return err
	}
	if err := protocol.ValidateManifest(record.Manifest); err != nil {
		return err
	}
	if record.Manifest.ArtifactDigest != record.ActiveDigest {
		return errors.New("connectorhost: connector manifest and active digest differ")
	}
	if record.PreviousDigest == "" {
		if record.PreviousFilename != "" || record.PreviousManifest != nil || len(record.PreviousSettings) != 0 || len(record.PreviousStorageOrigins) != 0 {
			return errors.New("connectorhost: incomplete connector rollback slot")
		}
		return nil
	}
	if err := protocol.ValidateArtifactDigest(record.PreviousDigest); err != nil {
		return err
	}
	if validateArtifactFilename(record.PreviousFilename) != nil || record.PreviousManifest == nil || len(record.PreviousSettings) == 0 || len(record.PreviousSettings) > protocol.MaxJobPayloadBytes || !json.Valid(record.PreviousSettings) {
		return errors.New("connectorhost: incomplete connector rollback slot")
	}
	if err := protocol.ValidateManifest(*record.PreviousManifest); err != nil {
		return err
	}
	if record.PreviousManifest.ArtifactDigest != record.PreviousDigest {
		return errors.New("connectorhost: rollback manifest and digest differ")
	}
	return nil
}

func validateHostStorageOrigins(origins []string) error {
	return protocol.ValidateHostConnectorInventoryMutationResponse(protocol.HostConnectorInventoryMutationResponse{
		InstallationID:       "00000000-0000-4000-8000-000000000001",
		AcknowledgedRevision: 1,
		StorageOrigins:       origins,
	})
}

func validateDisplayName(name string) error {
	if len(name) > protocol.MaxHostDisplayNameBytes || !utf8.ValidString(name) {
		return errors.New("connectorhost: connector display name must be valid UTF-8 within the size limit")
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return errors.New("connectorhost: connector display name must not contain control characters")
		}
	}
	return nil
}
