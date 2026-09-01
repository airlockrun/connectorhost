package connectorhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

type Host struct {
	store              *Store
	installer          *ArtifactInstaller
	supervisor         *Supervisor
	clientMu           sync.RWMutex
	client             *ControlClient
	httpClient         *http.Client
	logger             *slog.Logger
	stateChanged       chan struct{}
	accessMu           sync.Mutex
	enrollmentMu       sync.Mutex
	credentialsReady   chan struct{}
	managementMu       sync.Mutex
	activeManagementMu sync.RWMutex
	activeManagement   map[string]protocol.ActiveAttempt
}

func NewHost(store *Store, httpClient *http.Client, logger *slog.Logger) *Host {
	if store == nil || logger == nil {
		panic("connectorhost: store and logger are required")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	host := &Host{store: store, httpClient: httpClient, logger: logger, credentialsReady: make(chan struct{}, 1), stateChanged: make(chan struct{}, 1), activeManagement: make(map[string]protocol.ActiveAttempt)}
	host.installer = NewArtifactInstaller(store, httpClient)
	host.supervisor = NewSupervisor(store, host)
	return host
}

func (h *Host) Serve(ctx context.Context) error {
	return h.ServeControl(ctx, DefaultControlPort)
}

func (h *Host) ServeControl(ctx context.Context, controlPort int) error {
	h.logger.Info("host service starting", "state_directory", h.store.Root(), "control_port", controlPort, "access_mode", h.store.AccessMode(), "version", Version)
	h.CleanupStaging()
	control, err := NewLocalControlServer(h, controlPort)
	if err != nil {
		return err
	}
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	controlResult := make(chan error, 1)
	go func() {
		controlResult <- control.Serve(serveCtx)
		cancel()
	}()
	remoteErr := h.serveRemote(serveCtx)
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	closeErr := control.Close(shutdownCtx)
	shutdownCancel()
	controlErr := <-controlResult
	if ctx.Err() != nil {
		remoteErr = nil
	}
	return errors.Join(remoteErr, controlErr, closeErr)
}

func (h *Host) serveRemote(ctx context.Context) error {
	baseURL, credential, err := h.waitForCredentials(ctx)
	if err != nil {
		return err
	}
	client, err := NewControlClient(baseURL, credential, h.httpClient)
	if err != nil {
		return err
	}
	h.clientMu.Lock()
	h.client = client
	h.clientMu.Unlock()
	h.logger.Info("control plane configured", "host_id", h.store.HostID())
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = h.supervisor.Close(stopCtx)
	}()
	h.managementMu.Lock()
	err = h.recoverInterruptedManagement(ctx)
	if err == nil {
		err = h.supervisor.StartAll(ctx)
	}
	h.managementMu.Unlock()
	if err != nil {
		return err
	}
	heartbeat := 30 * time.Second
	syncFailing := false
	pollFailing := false
	firstSync := true
	for {
		h.recoverManagementOutcomes(ctx)
		h.flushManagementOutcomes(ctx)
		mutationCtx, mutationCancel := context.WithTimeout(ctx, 10*time.Second)
		h.flushInventoryMutations(mutationCtx, client)
		mutationCancel()
		syncCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		response, err := client.Sync(syncCtx, h.syncRequest())
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !syncFailing {
				h.logger.Warn("host synchronization failed")
				syncFailing = true
			}
			if err := sleepContext(ctx, time.Second); err != nil {
				return nil
			}
			continue
		}
		if syncFailing {
			h.logger.Info("host synchronization recovered")
			syncFailing = false
		}
		if response.HostID != "" && response.HostID != h.store.HostID() {
			if err := h.store.SetCredentials(baseURL, credential, response.HostID); err != nil {
				return err
			}
		}
		if firstSync {
			h.logger.Info("host synchronized", "host_id", response.HostID, "access_mode", h.store.AccessMode(), "connectors", len(h.store.Connectors()))
			firstSync = false
		}
		h.retryConnectorStartup(ctx)
		if response.HeartbeatSeconds >= 5 && response.HeartbeatSeconds <= 3600 {
			heartbeat = time.Duration(response.HeartbeatSeconds) * time.Second
		}
		pollDeadline := heartbeat
		if response.LongPollSeconds > 0 && response.LongPollSeconds <= 300 {
			pollDeadline = time.Duration(response.LongPollSeconds+5) * time.Second
		}
		work, pollErr, stateChanged := h.poll(ctx, client, pollDeadline)
		if stateChanged {
			continue
		}
		if pollErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !pollFailing {
				h.logger.Warn("host work poll failed")
				pollFailing = true
			}
			continue
		}
		if pollFailing {
			h.logger.Info("host work polling recovered")
			pollFailing = false
		}
		for _, item := range work.Work {
			h.handleWork(ctx, item)
		}
	}
}

type hostPollResult struct {
	response protocol.HostPollResponse
	err      error
}

func (h *Host) poll(ctx context.Context, client *ControlClient, deadline time.Duration) (protocol.HostPollResponse, error, bool) {
	pollCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	result := make(chan hostPollResult, 1)
	go func() {
		response, err := client.Poll(pollCtx, protocol.HostPollRequest{ActiveManagementAttempts: h.managementAttempts(), ActiveConnectorAttempts: h.activeAttempts()})
		result <- hostPollResult{response: response, err: err}
	}()
	select {
	case completed := <-result:
		return completed.response, completed.err, false
	case <-h.stateChanged:
		cancel()
		<-result
		return protocol.HostPollResponse{}, nil, true
	case <-ctx.Done():
		cancel()
		<-result
		return protocol.HostPollResponse{}, ctx.Err(), false
	}
}

func (h *Host) SetAccessMode(mode AccessMode) error {
	h.accessMu.Lock()
	defer h.accessMu.Unlock()
	previous := h.store.AccessMode()
	if err := h.store.SetAccessMode(mode); err != nil {
		return err
	}
	if previous != mode {
		h.logger.Info("access mode changed", "previous", previous, "current", mode)
		select {
		case h.stateChanged <- struct{}{}:
		default:
		}
	}
	return nil
}

func (h *Host) waitForCredentials(ctx context.Context) (string, string, error) {
	for {
		baseURL, credential := h.store.Credentials()
		if baseURL != "" || credential != "" {
			return baseURL, credential, nil
		}
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-h.credentialsReady:
		}
	}
}

func (h *Host) signalCredentialsReady() {
	select {
	case h.credentialsReady <- struct{}{}:
	default:
	}
}

func (h *Host) retryConnectorStartup(ctx context.Context) {
	if !h.managementMu.TryLock() {
		return
	}
	go func() {
		defer h.managementMu.Unlock()
		_ = h.supervisor.StartFailure(ctx)
	}()
}

func (h *Host) syncRequest() protocol.HostSyncRequest {
	h.managementMu.Lock()
	defer h.managementMu.Unlock()
	name, _ := os.Hostname()
	acknowledged := make(map[string]bool)
	for _, record := range h.store.Connectors() {
		acknowledged[record.InstallationID] = record.InventoryAcknowledged
	}
	statuses := h.supervisor.Statuses()
	connectors := statuses[:0]
	for _, status := range statuses {
		if acknowledged[status.InstallationID] {
			connectors = append(connectors, status)
		}
	}
	return protocol.HostSyncRequest{Host: protocol.HostInfo{ProtocolVersion: protocol.HostProtocolVersion, Name: name, Platform: runtime.GOOS, Architecture: platformArchitecture(), AccessMode: h.store.AccessMode(), Version: Version}, Connectors: connectors}
}

func (h *Host) flushInventoryMutations(ctx context.Context, client *ControlClient) {
	mutations := h.store.PendingInventoryMutations()
	if len(mutations) == 0 {
		return
	}
	const workers = 8
	work := make(chan protocol.HostConnectorInventoryMutationRequest)
	var wait sync.WaitGroup
	for range min(workers, len(mutations)) {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for mutation := range work {
				response, err := client.InventoryMutation(ctx, mutation)
				if err != nil {
					continue
				}
				h.managementMu.Lock()
				before, existed := h.store.Connector(mutation.InstallationID)
				record, applied, err := h.store.AcknowledgeInventoryMutation(mutation, response)
				if err == nil && applied && mutation.Kind == protocol.HostConnectorMutationUpsert && (!existed || !slices.Equal(before.StorageOrigins, record.StorageOrigins)) {
					restartCtx, restartCancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
					_ = h.supervisor.Start(restartCtx, record.InstallationID)
					restartCancel()
				}
				h.managementMu.Unlock()
			}
		}()
	}
	for _, mutation := range mutations {
		select {
		case work <- mutation:
		case <-ctx.Done():
			close(work)
			wait.Wait()
			return
		}
	}
	close(work)
	wait.Wait()
}

func (h *Host) activeAttempts() []protocol.ActiveAttempt {
	var result []protocol.ActiveAttempt
	for _, status := range h.supervisor.Statuses() {
		result = append(result, status.ActiveAttempts...)
	}
	return result
}

func (h *Host) handleWork(ctx context.Context, work protocol.HostWork) {
	switch work.Kind {
	case protocol.HostWorkConnectorJob:
		if work.ConnectorJob == nil {
			return
		}
		h.logger.Info("connector command received", "connector_id", work.ConnectorID, "job_id", work.ConnectorJob.JobID, "kind", work.ConnectorJob.Kind, "operation", work.ConnectorJob.Operation)
		if err := h.supervisor.Dispatch(work.ConnectorID, *work.ConnectorJob); err != nil {
			h.logger.Warn("connector command dispatch failed", "connector_id", work.ConnectorID, "job_id", work.ConnectorJob.JobID)
			completion := protocol.JobCompletion{AttemptToken: work.ConnectorJob.AttemptToken, Status: "error", Error: err.Error()}
			completionCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			_ = retryControl(completionCtx, func(ctx context.Context) error {
				return h.controlClient().ConnectorCompletion(ctx, work.ConnectorID, work.ConnectorJob.JobID, completion)
			})
			cancel()
		}
	case protocol.HostWorkConnectorCancel:
		if work.Cancel != nil {
			h.logger.Info("connector command cancellation received", "connector_id", work.ConnectorID, "job_id", work.Cancel.JobID)
			_ = h.supervisor.Cancel(work.ConnectorID, *work.Cancel)
		}
	default:
		if work.ManagementJob != nil {
			h.activeManagementMu.Lock()
			if _, exists := h.activeManagement[work.ManagementJob.AttemptToken]; exists {
				h.activeManagementMu.Unlock()
				return
			}
			h.activeManagement[work.ManagementJob.AttemptToken] = protocol.ActiveAttempt{JobID: work.ManagementJob.JobID, AttemptToken: work.ManagementJob.AttemptToken}
			h.activeManagementMu.Unlock()
			go h.handleManagement(ctx, work.Kind, work.ConnectorID, *work.ManagementJob)
		}
	}
}

func (h *Host) handleManagement(parent context.Context, kind protocol.HostWorkKind, connectorID string, job protocol.HostManagementJob) {
	h.logger.Info("management work started", "kind", kind, "job_id", job.JobID, "connector_id", connectorID)
	defer func() {
		h.activeManagementMu.Lock()
		delete(h.activeManagement, job.AttemptToken)
		h.activeManagementMu.Unlock()
	}()
	h.managementMu.Lock()
	defer h.managementMu.Unlock()
	completion := protocol.HostManagementCompletion{JobID: job.JobID, AttemptToken: job.AttemptToken, Status: "error"}
	sendCompletion := true
	defer func() {
		if completion.Status == "success" {
			h.logger.Info("management work completed", "kind", kind, "job_id", job.JobID, "connector_id", connectorID, "status", completion.Status)
		} else {
			h.logger.Warn("management work completed", "kind", kind, "job_id", job.JobID, "connector_id", connectorID, "status", completion.Status)
		}
		if !sendCompletion {
			return
		}
		if err := retryControl(context.WithoutCancel(parent), func(ctx context.Context) error { return h.controlClient().ManagementCompletion(ctx, completion) }); err == nil {
			_ = h.store.removeManagementOutcome(job.JobID)
		}
	}()
	_, exists := h.store.Connector(connectorID)
	if !AllowsRemoteManagement(h.store.AccessMode(), kind, exists) {
		completion.Error = "connectorhost: local access policy denied management work"
		return
	}
	if job.JobID == "" || job.AttemptToken == "" || !job.Deadline.After(time.Now()) {
		completion.Error = "connectorhost: invalid or expired management job"
		return
	}
	ctx, cancel := context.WithDeadline(parent, job.Deadline)
	defer cancel()
	journal, found, err := h.store.loadManagementOutcome(job.JobID)
	if err != nil {
		completion.Error = err.Error()
		return
	}
	if found {
		if journal.Kind != kind || journal.ConnectorID != connectorID {
			completion.Error = "connectorhost: management job identity conflicts with its local journal"
			return
		}
		if journal.Status == "running" {
			if err := h.recoverInterruptedManagement(ctx); err != nil {
				sendCompletion = false
				return
			}
			journal, found, err = h.store.loadManagementOutcome(job.JobID)
			if err != nil || !found || journal.Status == "running" {
				sendCompletion = false
				return
			}
		}
		journal.AttemptToken = job.AttemptToken
		if err := h.store.saveManagementOutcome(journal); err != nil {
			sendCompletion = false
			return
		}
		completion.Status, completion.Output, completion.Error = journal.Status, journal.Output, journal.Error
		return
	}
	journal = managementOutcome{JobID: job.JobID, AttemptToken: job.AttemptToken, Kind: kind, ConnectorID: connectorID, Status: "running"}
	if connectorID != "" {
		before, existed := h.store.Connector(connectorID)
		journal.ConnectorExisted = existed
		if existed {
			journal.ConnectorBefore = &before
		}
	}
	if err := h.store.saveManagementOutcome(journal); err != nil {
		completion.Error = err.Error()
		return
	}
	if err := retryControl(ctx, func(ctx context.Context) error {
		return h.controlClient().ManagementEvent(ctx, job.JobID, protocol.HostManagementEvent{AttemptToken: job.AttemptToken, Sequence: 1, Phase: "started", Time: time.Now().UTC()})
	}); err != nil {
		completion.Error = err.Error()
		_ = h.store.removeManagementOutcome(job.JobID)
		return
	}
	var output any
	err = nil
	switch kind {
	case protocol.HostWorkShell:
		var input protocol.ShellInput
		if decodeErr := strictJSON(job.Input, &input); decodeErr != nil {
			err = decodeErr
		} else {
			output, err = ExecuteShell(ctx, input, func(processID int) error {
				journal.ProcessID = processID
				return h.store.saveManagementOutcome(journal)
			})
			journal.ProcessID = 0
		}
	case protocol.HostWorkConnectorInstall, protocol.HostWorkConnectorUpdate:
		var input protocol.ConnectorArtifactInput
		if decodeErr := strictJSON(job.Input, &input); decodeErr != nil {
			err = decodeErr
		} else {
			if input.InstallationID != "" && input.InstallationID != connectorID {
				err = errors.New("connectorhost: management connector ID does not match artifact input")
			} else {
				input.InstallationID = connectorID
				err = h.installRemote(ctx, input, kind == protocol.HostWorkConnectorUpdate)
			}
		}
	case protocol.HostWorkConnectorRemove:
		err = h.remove(ctx, connectorID, false)
	case protocol.HostWorkConnectorRollback:
		err = h.rollback(ctx, connectorID, false)
	default:
		err = fmt.Errorf("connectorhost: unsupported management work %q", kind)
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			completion.Status = "timeout"
		} else if errors.Is(err, context.Canceled) {
			completion.Status = "canceled"
		}
		completion.Error = err.Error()
		journal.Status, journal.Error = completion.Status, completion.Error
		if saveErr := h.store.saveManagementOutcome(journal); saveErr != nil {
			sendCompletion = false
		}
		return
	}
	completion.Status = "success"
	if output != nil {
		completion.Output, err = json.Marshal(output)
		if err != nil {
			completion.Status, completion.Error = "error", err.Error()
		}
	}
	journal.Status, journal.Output, journal.Error = completion.Status, completion.Output, completion.Error
	if err := h.store.saveManagementOutcome(journal); err != nil {
		sendCompletion = false
	}
}

func (h *Host) flushManagementOutcomes(ctx context.Context) {
	outcomes, err := h.store.managementOutcomes()
	if err != nil {
		return
	}
	for _, outcome := range outcomes {
		if outcome.Status == "running" {
			continue
		}
		completion := protocol.HostManagementCompletion{JobID: outcome.JobID, AttemptToken: outcome.AttemptToken, Status: outcome.Status, Output: outcome.Output, Error: outcome.Error}
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := h.controlClient().ManagementCompletion(requestCtx, completion)
		cancel()
		if err == nil {
			_ = h.store.removeManagementOutcome(outcome.JobID)
		}
	}
}

func (h *Host) recoverManagementOutcomes(ctx context.Context) {
	if !h.managementMu.TryLock() {
		return
	}
	defer h.managementMu.Unlock()
	_ = h.recoverInterruptedManagement(ctx)
}

func (h *Host) recoverInterruptedManagement(ctx context.Context) error {
	outcomes, err := h.store.managementOutcomes()
	if err != nil {
		return err
	}
	for _, outcome := range outcomes {
		if outcome.Status != "running" {
			continue
		}
		outcome.Status, outcome.Error = "error", "connectorhost: management operation was interrupted"
		if outcome.Kind == protocol.HostWorkShell {
			if err := terminateInterruptedShell(outcome.ProcessID); err != nil {
				outcome.Error = err.Error()
			}
			outcome.ProcessID = 0
			if err := h.store.saveManagementOutcome(outcome); err != nil {
				return err
			}
			continue
		}
		current, exists := h.store.Connector(outcome.ConnectorID)
		switch outcome.Kind {
		case protocol.HostWorkConnectorInstall:
			if !outcome.ConnectorExisted && exists {
				if startErr := h.supervisor.Start(ctx, outcome.ConnectorID); startErr == nil {
					outcome.Status, outcome.Error = "success", ""
				} else {
					if err := h.store.RemoveRemoteConnector(outcome.ConnectorID); err != nil {
						return err
					}
					if err := os.RemoveAll(filepath.Join(h.store.root, "connectors", outcome.ConnectorID)); err != nil {
						return err
					}
					outcome.Error = startErr.Error()
				}
			}
		case protocol.HostWorkConnectorUpdate:
			activated := outcome.ConnectorBefore != nil && exists && current.ActiveDigest != outcome.ConnectorBefore.ActiveDigest
			if activated {
				if startErr := h.supervisor.Start(ctx, outcome.ConnectorID); startErr == nil {
					outcome.Status, outcome.Error = "success", ""
				} else {
					outcome.Error = startErr.Error()
				}
			}
			if outcome.Status != "success" && outcome.ConnectorBefore != nil {
				if err := h.store.PutRemoteConnector(*outcome.ConnectorBefore); err != nil {
					return err
				}
				_ = h.supervisor.Start(ctx, outcome.ConnectorID)
			}
		case protocol.HostWorkConnectorRollback:
			activated := outcome.ConnectorBefore != nil && exists && rollbackSlotsSwapped(current, *outcome.ConnectorBefore)
			if activated {
				if startErr := h.supervisor.Start(ctx, outcome.ConnectorID); startErr == nil {
					outcome.Status, outcome.Error = "success", ""
				} else {
					outcome.Error = startErr.Error()
				}
			}
			if outcome.Status != "success" && outcome.ConnectorBefore != nil {
				if err := h.store.PutRemoteConnector(*outcome.ConnectorBefore); err != nil {
					return err
				}
				_ = h.supervisor.Start(ctx, outcome.ConnectorID)
			}
		case protocol.HostWorkConnectorRemove:
			if !exists {
				if err := os.RemoveAll(filepath.Join(h.store.root, "connectors", outcome.ConnectorID)); err != nil {
					return err
				}
				outcome.Status, outcome.Error = "success", ""
			} else if h.remove(ctx, outcome.ConnectorID, false) == nil {
				outcome.Status, outcome.Error = "success", ""
			}
		default:
			outcome.Error = "connectorhost: unsupported interrupted management operation"
		}
		if err := h.store.saveManagementOutcome(outcome); err != nil {
			return err
		}
	}
	return nil
}

func rollbackSlotsSwapped(current, before ConnectorRecord) bool {
	return before.PreviousManifest != nil && current.PreviousManifest != nil &&
		current.ActiveDigest == before.PreviousDigest && current.PreviousDigest == before.ActiveDigest &&
		current.Filename == before.PreviousFilename && current.PreviousFilename == before.Filename &&
		bytes.Equal(current.Settings, before.PreviousSettings) && bytes.Equal(current.PreviousSettings, before.Settings) &&
		slices.Equal(current.StorageOrigins, before.PreviousStorageOrigins) && slices.Equal(current.PreviousStorageOrigins, before.StorageOrigins) &&
		manifestsEqual(current.Manifest, *before.PreviousManifest) && manifestsEqual(*current.PreviousManifest, before.Manifest)
}

func manifestsEqual(left, right protocol.Manifest) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func (h *Host) Install(ctx context.Context, input protocol.ConnectorArtifactInput, update bool) error {
	h.managementMu.Lock()
	defer h.managementMu.Unlock()
	return h.installRemote(ctx, input, update)
}

func (h *Host) installRemote(ctx context.Context, input protocol.ConnectorArtifactInput, update bool) error {
	if err := validateHostStorageOrigins(input.StorageOrigins); err != nil {
		return fmt.Errorf("connectorhost: artifact storage origins: %w", err)
	}
	old, exists := h.store.Connector(input.InstallationID)
	if update != exists {
		if update {
			return errors.New("connectorhost: update requires an existing connector")
		}
		return errors.New("connectorhost: connector is already installed; use update")
	}
	if !update && len(h.store.Connectors()) >= protocol.MaxHostedConnectors {
		return errors.New("connectorhost: connector installation limit reached")
	}
	settings := input.Settings
	if len(settings) == 0 && exists {
		settings = old.Settings
		input.StorageOrigins = old.StorageOrigins
	}
	record, err := h.installer.Stage(ctx, input, settings)
	if err != nil {
		h.cleanupStagingFailure(input.InstallationID, old, exists)
		return err
	}
	if exists {
		record.DisplayName = old.DisplayName
		record.PreviousDigest, record.PreviousFilename = old.ActiveDigest, old.Filename
		record.PreviousSettings = append(json.RawMessage(nil), old.Settings...)
		record.PreviousStorageOrigins = append([]string(nil), old.StorageOrigins...)
		previousManifest := old.Manifest
		record.PreviousManifest = &previousManifest
	}
	if err := h.supervisor.Activate(ctx, record, func() error { return h.store.PutRemoteConnector(record) }); err != nil {
		restoreErr := h.store.rewriteCurrentState()
		if exists {
			restoreErr = errors.Join(restoreErr, h.supervisor.Start(context.Background(), old.InstallationID))
			h.cleanupFailedCandidate(old, record)
		} else {
			_ = os.RemoveAll(filepath.Join(h.store.root, "connectors", record.InstallationID))
		}
		return errors.Join(fmt.Errorf("connectorhost: candidate activation failed and was rolled back: %w", err), restoreErr)
	}
	h.cleanupConnectorArtifacts(record)
	return nil
}

func (h *Host) Remove(ctx context.Context, id string) error {
	h.managementMu.Lock()
	defer h.managementMu.Unlock()
	return h.remove(ctx, id, true)
}

func (h *Host) remove(ctx context.Context, id string, local bool) error {
	if local {
		if err := validateInventoryInstallationID(id); err != nil {
			return err
		}
	}
	if _, exists := h.store.Connector(id); !exists {
		return fmt.Errorf("connectorhost: connector %q is not installed", id)
	}
	if local && !h.store.CanEnqueueInventoryMutation(id) {
		return errors.New("connectorhost: pending inventory mutation limit reached")
	}
	if err := h.supervisor.Stop(ctx, id); err != nil {
		return err
	}
	var err error
	if local {
		err = h.store.RemoveLocalConnector(id)
	} else {
		err = h.store.RemoveRemoteConnector(id)
	}
	if err != nil {
		_ = h.supervisor.Start(context.Background(), id)
		return err
	}
	return os.RemoveAll(filepath.Join(h.store.root, "connectors", id))
}

func (h *Host) Rollback(ctx context.Context, id string) error {
	h.managementMu.Lock()
	defer h.managementMu.Unlock()
	return h.rollback(ctx, id, true)
}

func (h *Host) rollback(ctx context.Context, id string, local bool) error {
	if local {
		if err := validateInventoryInstallationID(id); err != nil {
			return err
		}
	}
	record, exists := h.store.Connector(id)
	if !exists {
		return fmt.Errorf("connectorhost: connector %q is not installed", id)
	}
	if record.PreviousDigest == "" || record.PreviousManifest == nil {
		return errors.New("connectorhost: connector has no rollback slot")
	}
	record.ActiveDigest, record.PreviousDigest = record.PreviousDigest, record.ActiveDigest
	record.Filename, record.PreviousFilename = record.PreviousFilename, record.Filename
	record.Settings, record.PreviousSettings = record.PreviousSettings, record.Settings
	record.StorageOrigins, record.PreviousStorageOrigins = record.PreviousStorageOrigins, record.StorageOrigins
	currentManifest := record.Manifest
	record.Manifest, record.PreviousManifest = *record.PreviousManifest, &currentManifest
	persist := func() error {
		if local {
			return h.store.PutLocalConnector(record)
		}
		return h.store.PutRemoteConnector(record)
	}
	if err := h.supervisor.Activate(ctx, record, persist); err != nil {
		restoreErr := h.store.rewriteCurrentState()
		restoreErr = errors.Join(restoreErr, h.supervisor.Start(context.Background(), id))
		h.cleanupFailedCandidate(record, record)
		return errors.Join(fmt.Errorf("connectorhost: rollback candidate failed readiness and active slot was restored: %w", err), restoreErr)
	}
	h.cleanupConnectorArtifacts(record)
	return nil
}

func (h *Host) InstallLocal(ctx context.Context, input LocalArtifactInput, update bool) (ConnectorRecord, error) {
	h.managementMu.Lock()
	defer h.managementMu.Unlock()
	return h.installLocal(ctx, input, update)
}

func (h *Host) installLocal(ctx context.Context, input LocalArtifactInput, update bool) (ConnectorRecord, error) {
	if err := validateInventoryInstallationID(input.InstallationID); err != nil {
		return ConnectorRecord{}, err
	}
	old, exists := h.store.Connector(input.InstallationID)
	if update != exists {
		if update {
			return ConnectorRecord{}, errors.New("connectorhost: update requires an existing connector")
		}
		return ConnectorRecord{}, errors.New("connectorhost: connector is already installed; use update")
	}
	if !update && len(h.store.Connectors()) >= protocol.MaxHostedConnectors {
		return ConnectorRecord{}, errors.New("connectorhost: connector installation limit reached")
	}
	if update && len(input.Settings) == 0 {
		input.Settings = old.Settings
	}
	record, err := h.installer.StageLocal(ctx, input)
	if err != nil {
		h.cleanupStagingFailure(input.InstallationID, old, exists)
		return ConnectorRecord{}, err
	}
	if exists {
		record.DisplayName = old.DisplayName
		record.InventoryAcknowledged = old.InventoryAcknowledged
		record.PreviousDigest, record.PreviousFilename = old.ActiveDigest, old.Filename
		record.PreviousSettings = append(json.RawMessage(nil), old.Settings...)
		record.PreviousStorageOrigins = append([]string(nil), old.StorageOrigins...)
		previousManifest := old.Manifest
		record.PreviousManifest = &previousManifest
	}
	if err := h.supervisor.Activate(ctx, record, func() error { return h.store.PutLocalConnector(record) }); err != nil {
		restoreErr := h.store.rewriteCurrentState()
		if exists {
			restoreErr = errors.Join(restoreErr, h.supervisor.Start(context.Background(), old.InstallationID))
			h.cleanupFailedCandidate(old, record)
		} else {
			_ = os.RemoveAll(filepath.Join(h.store.root, "connectors", record.InstallationID))
		}
		return ConnectorRecord{}, errors.Join(fmt.Errorf("connectorhost: candidate activation failed and was rolled back: %w", err), restoreErr)
	}
	h.cleanupConnectorArtifacts(record)
	return record, nil
}

func (h *Host) Close(ctx context.Context) error {
	return h.supervisor.Close(ctx)
}

func (h *Host) cleanupConnectorArtifacts(record ConnectorRecord) {
	directory := filepath.Join(h.store.root, "connectors", record.InstallationID, "artifacts")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.Name() != record.ActiveDigest && entry.Name() != record.PreviousDigest {
			_ = os.RemoveAll(filepath.Join(directory, entry.Name()))
		}
	}
}

func (h *Host) cleanupFailedCandidate(active, candidate ConnectorRecord) {
	if candidate.ActiveDigest != active.ActiveDigest && candidate.ActiveDigest != active.PreviousDigest {
		_ = os.RemoveAll(filepath.Join(h.store.root, "connectors", candidate.InstallationID, "artifacts", candidate.ActiveDigest))
	}
	_ = os.RemoveAll(filepath.Join(h.store.root, "connectors", candidate.InstallationID, "staging"))
}

func (h *Host) cleanupStagingFailure(id string, active ConnectorRecord, exists bool) {
	if validateInstallationID(id) != nil {
		return
	}
	directory := filepath.Join(h.store.root, "connectors", id)
	if !exists {
		_ = os.RemoveAll(directory)
		return
	}
	_ = os.RemoveAll(filepath.Join(directory, "staging"))
	h.cleanupConnectorArtifacts(active)
}

func (h *Host) CleanupStaging() {
	directory := filepath.Join(h.store.root, "connectors")
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		return
	}
	for _, entry := range entries {
		record, exists := h.store.Connector(entry.Name())
		if !exists || !entry.IsDir() {
			_ = os.RemoveAll(filepath.Join(directory, entry.Name()))
			continue
		}
		_ = os.RemoveAll(filepath.Join(directory, record.InstallationID, "staging"))
		h.cleanupConnectorArtifacts(record)
	}
}

func (h *Host) ConnectorEvent(ctx context.Context, connectorID, jobID string, event protocol.JobEvent) error {
	return retryControl(ctx, func(ctx context.Context) error {
		return h.controlClient().ConnectorEvent(ctx, connectorID, jobID, event)
	})
}
func (h *Host) ConnectorCompletion(ctx context.Context, connectorID, jobID string, completion protocol.JobCompletion) error {
	if completion.Status == "success" {
		h.logger.Info("connector command completed", "connector_id", connectorID, "job_id", jobID, "status", completion.Status)
	} else {
		h.logger.Warn("connector command completed", "connector_id", connectorID, "job_id", jobID, "status", completion.Status)
	}
	return retryControl(ctx, func(ctx context.Context) error {
		return h.controlClient().ConnectorCompletion(ctx, connectorID, jobID, completion)
	})
}
func (h *Host) controlClient() *ControlClient {
	h.clientMu.RLock()
	defer h.clientMu.RUnlock()
	return h.client
}
func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (h *Host) managementAttempts() []protocol.ActiveAttempt {
	h.activeManagementMu.RLock()
	defer h.activeManagementMu.RUnlock()
	result := make([]protocol.ActiveAttempt, 0, len(h.activeManagement))
	for _, attempt := range h.activeManagement {
		result = append(result, attempt)
	}
	return result
}

func retryControl(ctx context.Context, operation func(context.Context) error) error {
	var err error
	backoff := 100 * time.Millisecond
	for attempt := 0; attempt < 5; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = operation(attemptCtx)
		cancel()
		if err == nil {
			return nil
		}
		if sleepContext(ctx, backoff) != nil {
			return errors.Join(err, ctx.Err())
		}
		backoff *= 2
	}
	return err
}
