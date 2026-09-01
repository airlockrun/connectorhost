package connectorhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

const maxArtifactBytes = 1 << 30

type LocalArtifactInput struct {
	InstallationID string
	SourcePath     string
	DisplayName    string
	ExpectedSHA256 string
	Settings       json.RawMessage
}

type ArtifactInstaller struct {
	store  *Store
	client *http.Client
}

func NewArtifactInstaller(store *Store, client *http.Client) *ArtifactInstaller {
	if store == nil {
		panic("connectorhost: artifact store is required")
	}
	return &ArtifactInstaller{store: store, client: noProxyHTTPClient(client, 30*time.Minute)}
}

func (i *ArtifactInstaller) Stage(ctx context.Context, input protocol.ConnectorArtifactInput, settings json.RawMessage) (ConnectorRecord, error) {
	if err := validateInstallationID(input.InstallationID); err != nil {
		return ConnectorRecord{}, err
	}
	if err := validateHostStorageOrigins(input.StorageOrigins); err != nil {
		return ConnectorRecord{}, fmt.Errorf("connectorhost: artifact storage origins: %w", err)
	}
	parsed, err := url.Parse(input.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return ConnectorRecord{}, errors.New("connectorhost: artifact URL must be an exact HTTPS URL without user information or a fragment")
	}
	if err := validateArtifactFilename(input.Filename); err != nil {
		return ConnectorRecord{}, err
	}
	if err := validateExpectedDigest(input.SHA256, false); err != nil {
		return ConnectorRecord{}, err
	}
	if input.SizeBytes < 1 || input.SizeBytes > maxArtifactBytes {
		return ConnectorRecord{}, fmt.Errorf("connectorhost: artifact size must be between 1 and %d bytes", maxArtifactBytes)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, input.URL, nil)
	if err != nil {
		return ConnectorRecord{}, err
	}
	response, err := i.client.Do(request)
	if err != nil {
		return ConnectorRecord{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ConnectorRecord{}, fmt.Errorf("connectorhost: artifact download returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength >= 0 && response.ContentLength != input.SizeBytes {
		return ConnectorRecord{}, errors.New("connectorhost: artifact Content-Length does not match declared size")
	}
	return i.stage(ctx, input.InstallationID, input.Filename, "", input.SHA256, input.SizeBytes, response.Body, settings, input.StorageOrigins)
}

func (i *ArtifactInstaller) StageLocal(ctx context.Context, input LocalArtifactInput) (ConnectorRecord, error) {
	if err := validateInstallationID(input.InstallationID); err != nil {
		return ConnectorRecord{}, err
	}
	if input.SourcePath == "" || !filepath.IsAbs(input.SourcePath) {
		return ConnectorRecord{}, errors.New("connectorhost: local artifact path must be absolute")
	}
	if err := validateExpectedDigest(input.ExpectedSHA256, true); err != nil {
		return ConnectorRecord{}, err
	}
	if err := validateDisplayName(input.DisplayName); err != nil {
		return ConnectorRecord{}, err
	}
	file, err := os.Open(input.SourcePath)
	if err != nil {
		return ConnectorRecord{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return ConnectorRecord{}, err
	}
	if !info.Mode().IsRegular() {
		return ConnectorRecord{}, errors.New("connectorhost: local artifact must be a regular file")
	}
	if info.Size() < 1 || info.Size() > maxArtifactBytes {
		return ConnectorRecord{}, fmt.Errorf("connectorhost: artifact size must be between 1 and %d bytes", maxArtifactBytes)
	}
	filename := filepath.Base(input.SourcePath)
	if err := validateArtifactFilename(filename); err != nil {
		return ConnectorRecord{}, err
	}
	return i.stage(ctx, input.InstallationID, filename, input.DisplayName, input.ExpectedSHA256, info.Size(), file, input.Settings, nil)
}

func (i *ArtifactInstaller) stage(ctx context.Context, installationID, filename, displayName, expectedDigest string, size int64, source io.Reader, settings json.RawMessage, storageOrigins []string) (ConnectorRecord, error) {
	if err := validateInstallationID(installationID); err != nil {
		return ConnectorRecord{}, err
	}
	if len(settings) == 0 {
		settings = json.RawMessage(`{}`)
	}
	if len(settings) > protocol.MaxJobPayloadBytes || !json.Valid(settings) {
		return ConnectorRecord{}, errors.New("connectorhost: settings must be bounded valid JSON")
	}
	root := filepath.Join(i.store.root, "connectors", installationID)
	stagingDirectory := filepath.Join(root, "staging")
	if err := os.MkdirAll(stagingDirectory, 0o700); err != nil {
		return ConnectorRecord{}, err
	}
	pattern := ".artifact-*"
	if strings.EqualFold(filepath.Ext(filename), ".exe") {
		pattern += ".exe"
	}
	temporary, err := os.CreateTemp(stagingDirectory, pattern)
	if err != nil {
		return ConnectorRecord{}, err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hasher), io.LimitReader(source, size+1))
	syncErr, closeErr := temporary.Sync(), temporary.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		return ConnectorRecord{}, errors.Join(copyErr, syncErr, closeErr)
	}
	if written != size {
		return ConnectorRecord{}, fmt.Errorf("connectorhost: artifact size is %d, want %d", written, size)
	}
	actualDigest := hex.EncodeToString(hasher.Sum(nil))
	if expectedDigest != "" && actualDigest != expectedDigest {
		return ConnectorRecord{}, errors.New("connectorhost: artifact SHA-256 mismatch")
	}
	if err := os.Chmod(temporaryName, 0o700); err != nil {
		return ConnectorRecord{}, err
	}
	manifest, err := inspectManifest(ctx, temporaryName)
	if err != nil {
		return ConnectorRecord{}, err
	}
	if manifest.ArtifactDigest != actualDigest {
		return ConnectorRecord{}, errors.New("connectorhost: candidate manifest digest does not match staged bytes")
	}
	if err := validateManifestTarget(manifest); err != nil {
		return ConnectorRecord{}, err
	}
	if displayName == "" {
		displayName = manifest.Interface.Name
	}
	directory := filepath.Join(root, "artifacts", actualDigest)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return ConnectorRecord{}, err
	}
	destination, reused, err := reusableArtifact(directory, actualDigest)
	if err != nil {
		return ConnectorRecord{}, err
	}
	if !reused {
		destination = filepath.Join(directory, filename)
		if err := replaceFile(temporaryName, destination); err != nil {
			return ConnectorRecord{}, err
		}
		if err := syncDirectory(directory); err != nil {
			return ConnectorRecord{}, err
		}
	}
	return ConnectorRecord{
		InstallationID: installationID,
		DisplayName:    displayName,
		ActiveDigest:   actualDigest,
		Filename:       filepath.Base(destination),
		Settings:       append(json.RawMessage(nil), settings...),
		StorageOrigins: append([]string(nil), storageOrigins...),
		Manifest:       manifest,
		InstalledAt:    time.Now().UTC(),
	}, nil
}

func reusableArtifact(directory, digest string) (string, bool, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return "", false, err
	}
	if len(entries) > 1 {
		return "", false, errors.New("connectorhost: digest artifact directory contains multiple files")
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return "", false, errors.New("connectorhost: digest artifact directory contains an unexpected directory")
		}
		path := filepath.Join(directory, entry.Name())
		if err := verifyArtifactFile(path, digest); err != nil {
			return "", false, fmt.Errorf("connectorhost: verify reusable artifact: %w", err)
		}
		return path, true, nil
	}
	return "", false, nil
}

func verifyArtifactFile(path, digest string) error {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !pathInfo.Mode().IsRegular() {
		return errors.New("artifact path is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxArtifactBytes {
		return errors.New("artifact is not a bounded regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return errors.New("artifact is not executable")
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.LimitReader(file, maxArtifactBytes+1)); err != nil {
		return err
	}
	if hex.EncodeToString(hasher.Sum(nil)) != digest {
		return errors.New("artifact SHA-256 does not match its installed record")
	}
	return nil
}

func validateArtifactFilename(filename string) error {
	if filename == "" || filepath.Base(filename) != filename || strings.ContainsAny(filename, `/\\`) {
		return errors.New("connectorhost: artifact filename must be a base name")
	}
	return nil
}

func validateExpectedDigest(digest string, optional bool) error {
	if digest == "" && optional {
		return nil
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size || digest != hex.EncodeToString(decoded) {
		return errors.New("connectorhost: artifact SHA-256 must be lowercase hexadecimal")
	}
	return nil
}

func validateManifestTarget(manifest protocol.Manifest) error {
	hostTarget := runtime.GOOS + "-" + platformArchitecture()
	for _, target := range manifest.Targets {
		if target == hostTarget {
			return nil
		}
	}
	return fmt.Errorf("connectorhost: candidate does not declare host target %s", hostTarget)
}

func inspectManifest(parent context.Context, executable string) (protocol.Manifest, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	command := exec.Command(executable, "manifest")
	configureContainedCommand(command)
	var stdout, stderr boundedBuffer
	stdout.limit, stderr.limit = protocol.MaxManifestBytes, 64<<10
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		return protocol.Manifest{}, err
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		return protocol.Manifest{}, err
	}
	command.Stdout, command.Stderr = stdoutWriter, stderrWriter
	if err := command.Start(); err != nil {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		_ = stderrReader.Close()
		_ = stderrWriter.Close()
		return protocol.Manifest{}, fmt.Errorf("connectorhost: start candidate manifest inspection: %w", err)
	}
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	terminate, cleanup, err := containedCommandStarted(command)
	if err != nil {
		_ = stdoutReader.Close()
		_ = stderrReader.Close()
		_ = command.Wait()
		return protocol.Manifest{}, fmt.Errorf("connectorhost: contain candidate manifest inspection: %w", err)
	}
	stdoutDone := copyManifestOutput(stdoutReader, &stdout)
	stderrDone := copyManifestOutput(stderrReader, &stderr)
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	var waitErr error
	select {
	case waitErr = <-wait:
		cleanup()
		waitManifestOutput(stdoutReader, stderrReader, stdoutDone, stderrDone)
	case <-ctx.Done():
		_ = terminate()
		_ = stdoutReader.Close()
		_ = stderrReader.Close()
		waitErr = <-wait
		cleanup()
		<-stdoutDone
		<-stderrDone
		if parent.Err() != nil {
			return protocol.Manifest{}, parent.Err()
		}
		return protocol.Manifest{}, errors.New("connectorhost: candidate manifest inspection timed out")
	}
	if waitErr != nil {
		return protocol.Manifest{}, fmt.Errorf("connectorhost: inspect candidate manifest: %w: %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	if stdout.overflow {
		return protocol.Manifest{}, errors.New("connectorhost: candidate manifest exceeds size limit")
	}
	if stderr.overflow {
		return protocol.Manifest{}, errors.New("connectorhost: candidate manifest stderr exceeds size limit")
	}
	var manifest protocol.Manifest
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, fmt.Errorf("connectorhost: decode candidate manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return manifest, errors.New("connectorhost: candidate manifest has trailing JSON")
	}
	if err := protocol.ValidateManifest(manifest); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func copyManifestOutput(reader *os.File, output *boundedBuffer) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(output, reader)
		_ = reader.Close()
		done <- err
	}()
	return done
}

func waitManifestOutput(stdout, stderr *os.File, stdoutDone, stderrDone <-chan error) {
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for stdoutDone != nil || stderrDone != nil {
		select {
		case <-stdoutDone:
			stdoutDone = nil
		case <-stderrDone:
			stderrDone = nil
		case <-timer.C:
			_ = stdout.Close()
			_ = stderr.Close()
			if stdoutDone != nil {
				<-stdoutDone
			}
			if stderrDone != nil {
				<-stderrDone
			}
			return
		}
	}
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := b.limit - b.buffer.Len()
	if remaining < len(value) {
		b.overflow = true
		if remaining < 0 {
			remaining = 0
		}
		value = value[:remaining]
	}
	_, _ = b.buffer.Write(value)
	return original, nil
}

func (b *boundedBuffer) Bytes() []byte  { return b.buffer.Bytes() }
func (b *boundedBuffer) String() string { return b.buffer.String() }
