package connectorhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

const (
	childWriteTimeout = 5 * time.Second
	childStopTimeout  = 10 * time.Second
)

type EventSink interface {
	ConnectorEvent(context.Context, string, string, protocol.JobEvent) error
	ConnectorCompletion(context.Context, string, string, protocol.JobCompletion) error
}

type Supervisor struct {
	store    *Store
	sink     EventSink
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.RWMutex
	dispatch sync.Mutex
	children map[string]*childProcess
	failures map[string]string
}

type childProcess struct {
	id          string
	command     *exec.Cmd
	input       io.WriteCloser
	encoder     *protocol.ChildEncoder
	terminate   func() error
	done        chan struct{}
	processDone chan error
	finishOnce  sync.Once
	err         error
	stopping    atomic.Bool
	mu          sync.RWMutex
	ready       protocol.ChildReady
	active      map[string]protocol.JobRequest
}

func NewSupervisor(store *Store, sink EventSink) *Supervisor {
	ctx, cancel := context.WithCancel(context.Background())
	return &Supervisor{store: store, sink: sink, ctx: ctx, cancel: cancel, children: make(map[string]*childProcess), failures: make(map[string]string)}
}

func (s *Supervisor) StartAll(ctx context.Context) error {
	var result error
	for _, record := range s.store.Connectors() {
		if err := s.Start(ctx, record.InstallationID); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (s *Supervisor) StartFailure(ctx context.Context) error {
	s.mu.RLock()
	ids := make([]string, 0, len(s.failures))
	for id := range s.failures {
		if s.children[id] == nil {
			ids = append(ids, id)
		}
	}
	s.mu.RUnlock()
	if len(ids) == 0 {
		return nil
	}
	sort.Strings(ids)
	return s.Start(ctx, ids[0])
}

func (s *Supervisor) Start(ctx context.Context, id string) error {
	record, ok := s.store.Connector(id)
	if !ok {
		return fmt.Errorf("connectorhost: connector %q is not installed", id)
	}
	if err := s.Stop(ctx, id); err != nil {
		return err
	}
	child, err := s.launch(ctx, record)
	if err != nil {
		s.mu.Lock()
		s.failures[id] = err.Error()
		s.mu.Unlock()
		return err
	}
	s.mu.Lock()
	s.children[id] = child
	delete(s.failures, id)
	s.mu.Unlock()
	go s.watch(id, child)
	return nil
}

func (s *Supervisor) Activate(ctx context.Context, record ConnectorRecord, persist func() error) error {
	if persist == nil {
		panic("connectorhost: activation persistence is required")
	}
	if err := s.Stop(ctx, record.InstallationID); err != nil {
		return err
	}
	child, err := s.launch(ctx, record)
	if err != nil {
		return err
	}
	if err := persist(); err != nil {
		_ = stopChild(context.Background(), child)
		return err
	}
	s.mu.Lock()
	s.children[record.InstallationID] = child
	delete(s.failures, record.InstallationID)
	s.mu.Unlock()
	go s.watch(record.InstallationID, child)
	return nil
}

func (s *Supervisor) launch(ctx context.Context, record ConnectorRecord) (*childProcess, error) {
	executable := s.store.Executable(record)
	if err := verifyArtifactFile(executable, record.ActiveDigest); err != nil {
		return nil, fmt.Errorf("connectorhost: verify installed connector %q: %w", record.InstallationID, err)
	}
	command := exec.Command(executable)
	command.Dir = filepath.Dir(executable)
	configureContainedCommand(command)
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	log, err := s.openLog(record.InstallationID)
	if err != nil {
		return nil, err
	}
	command.Stderr = log
	if err := command.Start(); err != nil {
		_ = log.Close()
		return nil, err
	}
	terminate, cleanup, err := containedCommandStarted(command)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = log.Close()
		return nil, err
	}
	child := &childProcess{id: record.InstallationID, command: command, input: stdin, encoder: protocol.NewChildEncoder(stdin), terminate: terminate, done: make(chan struct{}), processDone: make(chan error, 1), active: make(map[string]protocol.JobRequest)}
	go func() {
		err := command.Wait()
		cleanup()
		child.finish(err)
		child.processDone <- err
	}()
	decoder := protocol.NewChildDecoder(stdout)
	first := make(chan error, 1)
	go func() {
		defer log.Close()
		var envelope protocol.ChildEnvelope
		if err := decoder.Decode(&envelope); err != nil {
			first <- err
			child.finish(err)
			return
		}
		if envelope.Type != protocol.ChildMessageReady || envelope.Ready.ProtocolVersion != protocol.HostProtocolVersion {
			err := errors.New("connectorhost: child returned invalid readiness handshake")
			first <- err
			child.finish(err)
			return
		}
		child.setReady(*envelope.Ready)
		if envelope.Ready.Readiness != protocol.ReadinessReady {
			err := fmt.Errorf("connectorhost: connector is %s: %s", envelope.Ready.Readiness, envelope.Ready.Error)
			first <- err
			child.finish(err)
			return
		}
		if !manifestsEqual(envelope.Ready.Manifest, record.Manifest) {
			err := errors.New("connectorhost: child readiness manifest does not match installed record")
			first <- err
			child.finish(err)
			return
		}
		first <- nil
		for {
			if err := decoder.Decode(&envelope); err != nil {
				_ = child.terminate()
				child.finish(err)
				return
			}
			switch envelope.Type {
			case protocol.ChildMessageEvent:
				job, ok := child.job(envelope.Event.AttemptToken)
				if ok && s.sink != nil {
					_ = s.sink.ConnectorEvent(s.ctx, child.id, job.JobID, *envelope.Event)
				}
			case protocol.ChildMessageCompletion:
				job, ok := child.removeJob(envelope.Completion.AttemptToken)
				if ok && s.sink != nil {
					_ = s.sink.ConnectorCompletion(context.WithoutCancel(s.ctx), child.id, job.JobID, *envelope.Completion)
				}
			case protocol.ChildMessageReady:
				child.setReady(*envelope.Ready)
			default:
				err := fmt.Errorf("connectorhost: child sent invalid message %q", envelope.Type)
				_ = child.terminate()
				child.finish(err)
				return
			}
		}
	}()
	initialization := protocol.ChildInitialize{ProtocolVersion: protocol.HostProtocolVersion, InstallationID: record.InstallationID, Settings: record.Settings, StateDirectory: s.store.ChildStateDirectory(record.InstallationID), StorageOrigins: record.StorageOrigins}
	readyCtx, readyCancel := context.WithTimeout(ctx, 30*time.Second)
	defer readyCancel()
	if err := child.encode(readyCtx, protocol.ChildEnvelope{Type: protocol.ChildMessageInitialize, Initialize: &initialization}); err != nil {
		child.closeAndTerminate()
		return nil, err
	}
	select {
	case err := <-first:
		if err != nil {
			child.closeAndTerminate()
			return nil, err
		}
		return child, nil
	case <-readyCtx.Done():
		child.closeAndTerminate()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("connectorhost: connector readiness timed out")
	}
}

func (s *Supervisor) watch(id string, child *childProcess) {
	<-child.done
	err := child.waitError()
	if child.stopping.Load() || s.ctx.Err() != nil {
		return
	}
	child.mu.Lock()
	child.ready.Readiness, child.ready.Error = protocol.ReadinessOffline, err.Error()
	child.mu.Unlock()
	backoff := time.Second
	for s.ctx.Err() == nil {
		timer := time.NewTimer(backoff)
		select {
		case <-s.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		record, ok := s.store.Connector(id)
		if !ok {
			return
		}
		next, launchErr := s.launch(s.ctx, record)
		if launchErr != nil {
			s.mu.Lock()
			s.failures[id] = launchErr.Error()
			s.mu.Unlock()
			if backoff < time.Minute {
				backoff *= 2
			}
			continue
		}
		s.mu.Lock()
		installed := false
		if s.children[id] == child {
			s.children[id] = next
			delete(s.failures, id)
			installed = true
		}
		s.mu.Unlock()
		if !installed {
			next.stopping.Store(true)
			stopCtx, cancel := context.WithTimeout(context.Background(), childStopTimeout)
			_ = stopChild(stopCtx, next)
			cancel()
			return
		}
		child = next
		<-child.done
		err = child.waitError()
		if child.stopping.Load() {
			return
		}
		backoff = time.Second
	}
}

func (s *Supervisor) Stop(ctx context.Context, id string) error {
	s.mu.Lock()
	child := s.children[id]
	delete(s.children, id)
	s.mu.Unlock()
	if child == nil {
		return nil
	}
	return stopChild(ctx, child)
}

func stopChild(ctx context.Context, child *childProcess) error {
	child.stopping.Store(true)
	stopCtx, cancel := context.WithTimeout(ctx, childStopTimeout)
	defer cancel()
	child.mu.RLock()
	active := make([]protocol.JobRequest, 0, len(child.active))
	for _, job := range child.active {
		active = append(active, job)
	}
	child.mu.RUnlock()
	for _, job := range active {
		message := protocol.ChildCancel{JobID: job.JobID, AttemptToken: job.AttemptToken}
		if err := child.encode(stopCtx, protocol.ChildEnvelope{Type: protocol.ChildMessageCancel, Cancel: &message}); err != nil {
			child.closeAndTerminate()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.New("connectorhost: connector did not stop gracefully")
		}
	}
	_ = child.input.Close()
	select {
	case <-child.processDone:
		return nil
	case <-stopCtx.Done():
		child.closeAndTerminate()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("connectorhost: connector did not stop gracefully")
	}
}

func (s *Supervisor) Close(ctx context.Context) error {
	s.cancel()
	s.mu.RLock()
	ids := make([]string, 0, len(s.children))
	for id := range s.children {
		ids = append(ids, id)
	}
	s.mu.RUnlock()
	var result error
	for _, id := range ids {
		result = errors.Join(result, s.Stop(ctx, id))
	}
	return result
}

func (s *Supervisor) Dispatch(id string, job protocol.JobRequest) error {
	s.dispatch.Lock()
	defer s.dispatch.Unlock()
	if s.ActiveCount() >= protocol.MaxActiveAttempts {
		return errors.New("connectorhost: active connector attempt limit reached")
	}
	s.mu.RLock()
	child := s.children[id]
	s.mu.RUnlock()
	if child == nil {
		return fmt.Errorf("connectorhost: connector %q is offline", id)
	}
	child.mu.Lock()
	if child.ready.Readiness != protocol.ReadinessReady {
		child.mu.Unlock()
		return fmt.Errorf("connectorhost: connector %q is not ready", id)
	}
	if _, exists := child.active[job.AttemptToken]; exists {
		child.mu.Unlock()
		return errors.New("connectorhost: duplicate active attempt token")
	}
	child.active[job.AttemptToken] = job
	child.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), childWriteTimeout)
	err := child.encode(ctx, protocol.ChildEnvelope{Type: protocol.ChildMessageJob, Job: &job})
	cancel()
	if err != nil {
		child.removeJob(job.AttemptToken)
		return err
	}
	return nil
}

func (s *Supervisor) ActiveCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := 0
	for _, child := range s.children {
		child.mu.RLock()
		total += len(child.active)
		child.mu.RUnlock()
	}
	return total
}

func (s *Supervisor) Cancel(id string, cancel protocol.ChildCancel) error {
	s.mu.RLock()
	child := s.children[id]
	s.mu.RUnlock()
	if child == nil {
		return nil
	}
	ctx, stop := context.WithTimeout(context.Background(), childWriteTimeout)
	defer stop()
	return child.encode(ctx, protocol.ChildEnvelope{Type: protocol.ChildMessageCancel, Cancel: &cancel})
}

func (s *Supervisor) Statuses() []protocol.HostedConnectorStatus {
	records := s.store.Connectors()
	result := make([]protocol.HostedConnectorStatus, 0, len(records))
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, record := range records {
		status := protocol.HostedConnectorStatus{InstallationID: record.InstallationID, Manifest: protocol.SummarizeManifest(record.Manifest), Readiness: protocol.ReadinessOffline}
		if child := s.children[record.InstallationID]; child != nil {
			child.mu.RLock()
			status.Readiness, status.Error = child.ready.Readiness, child.ready.Error
			for _, job := range child.active {
				status.ActiveAttempts = append(status.ActiveAttempts, protocol.ActiveAttempt{JobID: job.JobID, AttemptToken: job.AttemptToken})
			}
			child.mu.RUnlock()
			sort.Slice(status.ActiveAttempts, func(i, j int) bool { return status.ActiveAttempts[i].JobID < status.ActiveAttempts[j].JobID })
		} else {
			status.Error = s.failures[record.InstallationID]
		}
		if len(status.Error) > protocol.MaxHostedStatusErrorBytes {
			status.Error = status.Error[:protocol.MaxHostedStatusErrorBytes]
		}
		result = append(result, status)
	}
	return result
}

func (c *childProcess) job(token string) (protocol.JobRequest, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	job, ok := c.active[token]
	return job, ok
}
func (c *childProcess) removeJob(token string) (protocol.JobRequest, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	job, ok := c.active[token]
	delete(c.active, token)
	return job, ok
}
func (c *childProcess) setReady(ready protocol.ChildReady) {
	c.mu.Lock()
	c.ready = ready
	c.mu.Unlock()
}
func (c *childProcess) encode(ctx context.Context, envelope protocol.ChildEnvelope) error {
	result := make(chan error, 1)
	go func() { result <- c.encoder.Encode(envelope) }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		c.closeAndTerminate()
		return ctx.Err()
	}
}
func (c *childProcess) closeAndTerminate() {
	_ = c.input.Close()
	_ = c.terminate()
}
func (c *childProcess) finish(err error) {
	if err == nil {
		err = errors.New("connectorhost: connector exited")
	}
	c.finishOnce.Do(func() { c.mu.Lock(); c.err = err; c.mu.Unlock(); close(c.done) })
}
func (c *childProcess) waitError() error { c.mu.RLock(); defer c.mu.RUnlock(); return c.err }

func (s *Supervisor) openLog(id string) (*os.File, error) {
	directory := filepath.Join(s.store.root, "logs")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, id+".log")
	if info, err := os.Stat(path); err == nil && info.Size() > 10<<20 {
		_ = os.Remove(path + ".1")
		if err := os.Rename(path, path+".1"); err != nil {
			return nil, err
		}
	}
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
}
