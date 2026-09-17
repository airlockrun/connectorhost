package connectorhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

const maxOutboxBytes = 64 << 20
const maxOutboxEntries = 512
const maxRejectedEntries = 128
const maxRejectedBytes = 16 << 20

// The disk queue keeps child output independent of network backpressure. Entries
// are deleted only after a durable server acknowledgement, including after restart.
func (h *Host) enqueueOutcome(message protocol.HostMessage, jobID, token, suffix string) (err error) {
	defer func() {
		if err != nil {
			h.logger.Error("cannot durably record connector output; stopping host", "job_id", jobID, "error", err)
			select {
			case h.outputFailure <- err:
			default:
			}
		}
	}()
	h.outboxMu.Lock()
	defer h.outboxMu.Unlock()
	key := sha256.Sum256([]byte(jobID + "/" + token))
	message.ID, message.Protocol = hex.EncodeToString(key[:]), protocol.HostTransportProtocol
	body, err := json.Marshal(message)
	if err != nil {
		return err
	}
	if len(body) > (1<<20)+(64<<10) {
		return errors.New("connectorhost: output exceeds size limit")
	}
	directory := filepath.Join(h.store.root, "outbox")
	path := filepath.Join(directory, message.ID+"-"+suffix+".json")
	if existing, err := os.ReadFile(path); err == nil {
		if string(existing) == string(body) {
			return nil
		}
		return errors.New("connectorhost: conflicting outcome replay")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	size := int64(len(body))
	pending := 0
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		pending++
		info, err := entry.Info()
		if err != nil {
			return err
		}
		size += info.Size()
	}
	entryLimit, byteLimit := maxOutboxEntries, int64(maxOutboxBytes)
	if message.ConnectorEvent != nil {
		entryLimit -= protocol.MaxHostConnectorClaims
		byteLimit -= protocol.MaxHostConnectorClaims * ((1 << 20) + (64 << 10))
	}
	if pending >= entryLimit || size > byteLimit {
		return errors.New("connectorhost: durable output queue exhausted; restore control-plane connectivity")
	}
	return atomicWrite(path, body, 0o600)
}

func (h *Host) flushConnectorOutcomes(ctx context.Context) error {
	directory := filepath.Join(h.store.root, "outbox")
	h.outboxMu.Lock()
	err := h.pruneRejectedOutcomes(directory)
	h.outboxMu.Unlock()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		message, err := protocol.DecodeHostMessage(body)
		if err != nil {
			return err
		}
		requestCtx, stop := context.WithTimeout(ctx, 10*time.Second)
		err = h.controlClient().ack(requestCtx, message)
		stop()
		if err != nil {
			var rejected *ControlError
			if errors.As(err, &rejected) && (rejected.Code == 400 || rejected.Code == 403 || rejected.Code == 404 || rejected.Code == 409) {
				h.outboxMu.Lock()
				renameErr := os.Rename(path, path+".rejected")
				if renameErr == nil {
					renameErr = h.pruneRejectedOutcomes(directory)
				}
				if renameErr == nil {
					renameErr = syncDirectory(directory)
				}
				h.outboxMu.Unlock()
				if renameErr != nil {
					return renameErr
				}
				h.logger.Error("server rejected connector output; retained for operator inspection", "path", path+".rejected", "error", err)
				continue
			}
			return fmt.Errorf("connectorhost: unacknowledged durable output %s: %w", entry.Name(), err)
		}
		h.outboxMu.Lock()
		err = os.Remove(path)
		if err == nil {
			err = syncDirectory(directory)
		}
		h.outboxMu.Unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

// Caller holds outboxMu. Only explicitly rejected payloads are eligible for retention cleanup.
func (h *Host) pruneRejectedOutcomes(directory string) error {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var rejected []os.FileInfo
	var size int64
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".rejected" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rejected = append(rejected, info)
		size += info.Size()
	}
	sort.Slice(rejected, func(i, j int) bool {
		if rejected[i].ModTime().Equal(rejected[j].ModTime()) {
			return rejected[i].Name() < rejected[j].Name()
		}
		return rejected[i].ModTime().Before(rejected[j].ModTime())
	})
	removed := 0
	for len(rejected)-removed > maxRejectedEntries || size > maxRejectedBytes {
		info := rejected[removed]
		path := filepath.Join(directory, info.Name())
		if err := os.Remove(path); err != nil {
			return err
		}
		size -= info.Size()
		removed++
		h.logger.Warn("rejected connector output retention limit reached; removing oldest payload", "path", path)
	}
	if removed > 0 {
		return syncDirectory(directory)
	}
	return nil
}
