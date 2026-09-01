package connectorhost

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

const (
	DefaultControlPort   = 42927
	controlProtocol      = 1
	maxControlBodyBytes  = protocol.MaxJobPayloadBytes + (64 << 10)
	maxControlReplyBytes = 8 << 20
	controlTimeout       = 31 * time.Minute
	controlDescriptor    = "control.json"
)

type ControlDescriptor struct {
	Protocol int    `json:"protocol"`
	Port     int    `json:"port"`
	Token    string `json:"token"`
	PID      int    `json:"pid"`
	Nonce    string `json:"nonce"`
}

type LocalControlServer struct {
	root       string
	descriptor ControlDescriptor
	listener   net.Listener
	server     *http.Server
	closeOnce  sync.Once
}

func NewLocalControlServer(host *Host, port int) (*LocalControlServer, error) {
	if host == nil {
		panic("connectorhost: local control host is required")
	}
	if port < 0 || port > 65535 {
		return nil, errors.New("connectorhost: control port must be between 0 and 65535")
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		return nil, fmt.Errorf("connectorhost: listen on TCP4 loopback control port: %w", err)
	}
	actualPort := listener.Addr().(*net.TCPAddr).Port
	token, err := randomControlSecret(32)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	nonce, err := randomControlSecret(24)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	descriptor := ControlDescriptor{Protocol: controlProtocol, Port: actualPort, Token: token, PID: os.Getpid(), Nonce: nonce}
	body, err := json.Marshal(descriptor)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	body = append(body, '\n')
	if err := atomicWrite(filepath.Join(host.store.root, controlDescriptor), body, 0o600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	control := &LocalControlServer{root: host.store.root, descriptor: descriptor, listener: listener}
	control.server = &http.Server{
		Handler:           control.handler(host),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       time.Minute,
		WriteTimeout:      controlTimeout,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	return control, nil
}

func (s *LocalControlServer) Serve(ctx context.Context) error {
	shutdown := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = s.server.Shutdown(shutdownCtx)
			cancel()
		case <-shutdown:
		}
	}()
	err := s.server.Serve(s.listener)
	close(shutdown)
	cleanupErr := s.cleanupDescriptor()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return errors.Join(err, cleanupErr)
}

func (s *LocalControlServer) Close(ctx context.Context) error {
	var result error
	s.closeOnce.Do(func() {
		result = errors.Join(s.server.Shutdown(ctx), s.cleanupDescriptor())
	})
	return result
}

func (s *LocalControlServer) cleanupDescriptor() error {
	path := filepath.Join(s.root, controlDescriptor)
	descriptor, err := ReadControlDescriptor(s.root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if descriptor.Nonce != s.descriptor.Nonce {
		return nil
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncDirectory(s.root)
}

func (s *LocalControlServer) handler(host *Host) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if subtle.ConstantTimeCompare([]byte(request.Header.Get("Authorization")), []byte("Bearer "+s.descriptor.Token)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeControlError(w, http.StatusUnauthorized, "connectorhost: local control authentication required")
			return
		}
		if request.URL.RawQuery != "" {
			writeControlError(w, http.StatusBadRequest, "connectorhost: local control query strings are not supported")
			return
		}
		if request.Method == http.MethodGet && request.ContentLength > 0 {
			writeControlError(w, http.StatusBadRequest, "connectorhost: local control GET requests do not accept a body")
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), controlTimeout)
		defer cancel()
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v1/connectors":
			statuses, err := host.LocalStatuses("")
			writeControlResult(w, statuses, err)
		case request.Method == http.MethodPost && request.URL.Path == "/v1/connectors/status":
			var input LocalConnectorRequest
			if !decodeControlRequest(w, request, &input) {
				return
			}
			statuses, err := host.LocalStatuses(input.InstallationID)
			writeControlResult(w, statuses, err)
		case request.Method == http.MethodPost && request.URL.Path == "/v1/connectors/install":
			var input LocalInstallRequest
			if !decodeControlRequest(w, request, &input) {
				return
			}
			result, err := host.LocalInstall(ctx, input)
			writeControlResult(w, result, err)
		case request.Method == http.MethodPost && request.URL.Path == "/v1/connectors/update":
			var input LocalUpdateRequest
			if !decodeControlRequest(w, request, &input) {
				return
			}
			writeControlResult(w, struct{}{}, host.LocalUpdate(ctx, input))
		case request.Method == http.MethodPost && request.URL.Path == "/v1/connectors/rollback":
			var input LocalConnectorRequest
			if !decodeControlRequest(w, request, &input) {
				return
			}
			writeControlResult(w, struct{}{}, host.Rollback(ctx, input.InstallationID))
		case request.Method == http.MethodPost && request.URL.Path == "/v1/connectors/remove":
			var input LocalConnectorRequest
			if !decodeControlRequest(w, request, &input) {
				return
			}
			writeControlResult(w, struct{}{}, host.Remove(ctx, input.InstallationID))
		case request.Method == http.MethodGet && request.URL.Path == "/v1/access":
			writeControlResult(w, LocalAccessRequest{Mode: host.store.AccessMode()}, nil)
		case request.Method == http.MethodPost && request.URL.Path == "/v1/access":
			var input LocalAccessRequest
			if !decodeControlRequest(w, request, &input) {
				return
			}
			writeControlResult(w, struct{}{}, host.store.SetAccessMode(input.Mode))
		default:
			writeControlError(w, http.StatusNotFound, "connectorhost: local control endpoint not found")
		}
	})
}

func decodeControlRequest(w http.ResponseWriter, request *http.Request, output any) bool {
	mediaType := strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0])
	if mediaType != "application/json" {
		writeControlError(w, http.StatusUnsupportedMediaType, "connectorhost: local control requests require application/json")
		return false
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxControlBodyBytes+1))
	if err != nil {
		writeControlError(w, http.StatusBadRequest, err.Error())
		return false
	}
	if len(body) > maxControlBodyBytes {
		writeControlError(w, http.StatusRequestEntityTooLarge, "connectorhost: local control request exceeds size limit")
		return false
	}
	if err := strictJSON(body, output); err != nil {
		writeControlError(w, http.StatusBadRequest, err.Error())
		return false
	}
	return true
}

type controlError struct {
	Error string `json:"error"`
}

func writeControlResult(w http.ResponseWriter, result any, err error) {
	if err != nil {
		writeControlError(w, http.StatusBadRequest, err.Error())
		return
	}
	body, err := json.Marshal(result)
	if err != nil || len(body) > maxControlReplyBytes {
		writeControlError(w, http.StatusInternalServerError, "connectorhost: local control response exceeds size limit")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func writeControlError(w http.ResponseWriter, status int, message string) {
	if len(message) > 64<<10 {
		message = message[:64<<10]
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(controlError{Error: message})
}

func randomControlSecret(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func ReadControlDescriptor(root string) (ControlDescriptor, error) {
	path := filepath.Join(root, controlDescriptor)
	file, err := os.Open(path)
	if err != nil {
		return ControlDescriptor{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return ControlDescriptor{}, err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 4096 {
		return ControlDescriptor{}, errors.New("connectorhost: invalid local control descriptor file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return ControlDescriptor{}, errors.New("connectorhost: local control descriptor is not private")
	}
	body, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return ControlDescriptor{}, err
	}
	var descriptor ControlDescriptor
	if err := strictJSON(body, &descriptor); err != nil {
		return ControlDescriptor{}, err
	}
	if descriptor.Protocol != controlProtocol || descriptor.Port < 1 || descriptor.Port > 65535 || descriptor.PID < 1 {
		return ControlDescriptor{}, errors.New("connectorhost: invalid local control descriptor")
	}
	token, tokenErr := base64.RawURLEncoding.DecodeString(descriptor.Token)
	nonce, nonceErr := base64.RawURLEncoding.DecodeString(descriptor.Nonce)
	if tokenErr != nil || len(token) != 32 || nonceErr != nil || len(nonce) != 24 {
		return ControlDescriptor{}, errors.New("connectorhost: invalid local control descriptor credentials")
	}
	return descriptor, nil
}

type LocalControlClient struct {
	baseURL string
	token   string
	http    *http.Client
}

type LocalControlAPIError struct {
	Status int
	Text   string
}

func (e *LocalControlAPIError) Error() string { return e.Text }

func NewLocalControlClient(root string) (*LocalControlClient, error) {
	descriptor, err := ReadControlDescriptor(root)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp4", address)
	}
	client := &http.Client{
		Transport:     transport,
		Timeout:       controlTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &LocalControlClient{baseURL: "http://127.0.0.1:" + strconv.Itoa(descriptor.Port), token: descriptor.Token, http: client}, nil
}

func (c *LocalControlClient) Install(ctx context.Context, request LocalInstallRequest) (LocalInstallResponse, error) {
	var response LocalInstallResponse
	err := c.do(ctx, http.MethodPost, "/v1/connectors/install", request, &response)
	return response, err
}

func (c *LocalControlClient) Update(ctx context.Context, request LocalUpdateRequest) error {
	return c.do(ctx, http.MethodPost, "/v1/connectors/update", request, nil)
}

func (c *LocalControlClient) Rollback(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/connectors/rollback", LocalConnectorRequest{InstallationID: id}, nil)
}

func (c *LocalControlClient) Remove(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/connectors/remove", LocalConnectorRequest{InstallationID: id}, nil)
}

func (c *LocalControlClient) Statuses(ctx context.Context, id string) ([]LocalConnectorStatus, error) {
	var response []LocalConnectorStatus
	method, endpoint, input := http.MethodGet, "/v1/connectors", any(nil)
	if id != "" {
		method, endpoint, input = http.MethodPost, "/v1/connectors/status", LocalConnectorRequest{InstallationID: id}
	}
	err := c.do(ctx, method, endpoint, input, &response)
	return response, err
}

func (c *LocalControlClient) Access(ctx context.Context) (AccessMode, error) {
	var response LocalAccessRequest
	err := c.do(ctx, http.MethodGet, "/v1/access", nil, &response)
	return response.Mode, err
}

func (c *LocalControlClient) SetAccess(ctx context.Context, mode AccessMode) error {
	return c.do(ctx, http.MethodPost, "/v1/access", LocalAccessRequest{Mode: mode}, nil)
}

func (c *LocalControlClient) do(ctx context.Context, method, endpoint string, input, output any) error {
	var reader io.Reader
	if input != nil {
		body, err := json.Marshal(input)
		if err != nil {
			return err
		}
		if len(body) > maxControlBodyBytes {
			return errors.New("connectorhost: local control request exceeds size limit")
		}
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+endpoint, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	mediaType := strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])
	if mediaType != "application/json" {
		return errors.New("connectorhost: local control response is not application/json")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxControlReplyBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxControlReplyBytes {
		return errors.New("connectorhost: local control response exceeds size limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var failure controlError
		if strictJSON(body, &failure) != nil || failure.Error == "" {
			failure.Error = fmt.Sprintf("connectorhost: local control returned HTTP %d", response.StatusCode)
		}
		return &LocalControlAPIError{Status: response.StatusCode, Text: failure.Error}
	}
	if output == nil {
		return nil
	}
	return strictJSON(body, output)
}
