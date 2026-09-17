package connectorhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
	"github.com/coder/websocket"
)

type ControlClient struct {
	baseURL    string
	credential string
	http       *http.Client
	mu         sync.Mutex
	session    *controlSession
	sequence   atomic.Uint64
}

type controlSession struct {
	conn    *websocket.Conn
	done    chan struct{}
	pending map[string]chan protocol.HostMessage
}

type ControlError struct {
	Code    int
	Message string
}

func (e *ControlError) Error() string {
	return fmt.Sprintf("connectorhost: control error %d: %s", e.Code, e.Message)
}

func NewControlClient(baseURL, credential string, client *http.Client) (*ControlClient, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("connectorhost: Airlock URL must be an HTTPS origin")
	}
	if credential == "" {
		return nil, errors.New("connectorhost: Airlock credential is required")
	}
	if client == nil {
		client = http.DefaultClient
	}
	copy := *client
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &ControlClient{baseURL: "wss" + strings.TrimSuffix(baseURL, "/")[5:], credential: credential, http: &copy}, nil
}

// Connect installs the sole outbound session. Requests never create sockets.
func (c *ControlClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != nil {
		return errors.New("connectorhost: session already connected")
	}
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(dialCtx, c.baseURL+"/api/hosts/v1/connect", &websocket.DialOptions{HTTPClient: c.http, HTTPHeader: http.Header{"Authorization": {"Bearer " + c.credential}}, Subprotocols: []string{protocol.HostTransportProtocol}})
	if err != nil {
		return err
	}
	if conn.Subprotocol() != protocol.HostTransportProtocol {
		conn.CloseNow()
		return errors.New("connectorhost: incompatible host transport")
	}
	conn.SetReadLimit(protocol.MaxHostMessageBytes)
	s := &controlSession{conn: conn, done: make(chan struct{}), pending: make(map[string]chan protocol.HostMessage)}
	c.session = s
	go c.read(ctx, s)
	return nil
}

func (c *ControlClient) read(ctx context.Context, s *controlSession) {
	defer func() {
		s.conn.CloseNow()
		c.mu.Lock()
		if c.session == s {
			c.session = nil
		}
		close(s.done)
		c.mu.Unlock()
	}()
	for {
		kind, data, err := s.conn.Read(ctx)
		if err != nil || kind != websocket.MessageText {
			return
		}
		message, err := protocol.DecodeHostMessage(data)
		if err != nil || message.Sync != nil || message.Inventory != nil || message.Heartbeat != nil || message.Demand != nil || message.ConnectorEvent != nil || message.ConnectorCompletion != nil || message.ManagementEvent != nil || message.ManagementCompletion != nil {
			return
		}
		c.mu.Lock()
		pending := s.pending[message.ID]
		delete(s.pending, message.ID)
		c.mu.Unlock()
		if pending == nil {
			return
		}
		pending <- message
	}
}

func (c *ControlClient) Close() {
	c.mu.Lock()
	s := c.session
	c.mu.Unlock()
	if s != nil {
		s.conn.CloseNow()
		<-s.done
	}
}

func (c *ControlClient) call(ctx context.Context, request protocol.HostMessage) (protocol.HostMessage, error) {
	request.Protocol, request.ID = protocol.HostTransportProtocol, fmt.Sprint(c.sequence.Add(1))
	if err := request.Validate(); err != nil {
		return protocol.HostMessage{}, err
	}
	data, err := json.Marshal(request)
	if err != nil {
		return protocol.HostMessage{}, err
	}
	if len(data) > protocol.MaxHostMessageBytes {
		return protocol.HostMessage{}, errors.New("connectorhost: host message too large")
	}
	c.mu.Lock()
	s := c.session
	if s == nil || len(s.pending) >= protocol.MaxHostRequests {
		c.mu.Unlock()
		return protocol.HostMessage{}, errors.New("connectorhost: disconnected or request capacity exhausted")
	}
	reply := make(chan protocol.HostMessage, 1)
	s.pending[request.ID] = reply
	c.mu.Unlock()
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = s.conn.Write(writeCtx, websocket.MessageText, data)
	cancel()
	if err != nil {
		s.conn.CloseNow()
		return protocol.HostMessage{}, err
	}
	select {
	case response := <-reply:
		if response.Error != nil {
			return response, &ControlError{Code: response.Error.Code, Message: response.Error.Message}
		}
		return response, nil
	case <-ctx.Done():
		// Closing fences an unacknowledged demand and all its correlated replies.
		s.conn.CloseNow()
		return protocol.HostMessage{}, ctx.Err()
	case <-s.done:
		return protocol.HostMessage{}, errors.New("connectorhost: session disconnected")
	}
}

func (c *ControlClient) Sync(ctx context.Context, request protocol.HostSyncRequest) (protocol.HostSyncResponse, error) {
	r, err := c.call(ctx, protocol.HostMessage{Sync: &request})
	if err != nil {
		return protocol.HostSyncResponse{}, err
	}
	if r.Synced == nil {
		return protocol.HostSyncResponse{}, errors.New("connectorhost: expected sync response")
	}
	return *r.Synced, nil
}

func (c *ControlClient) InventoryMutation(ctx context.Context, request protocol.HostConnectorInventoryMutationRequest) (protocol.HostConnectorInventoryMutationResponse, error) {
	if err := protocol.ValidateHostConnectorInventoryMutationRequest(request); err != nil {
		return protocol.HostConnectorInventoryMutationResponse{}, err
	}
	r, err := c.call(ctx, protocol.HostMessage{Inventory: &request})
	if err != nil {
		return protocol.HostConnectorInventoryMutationResponse{}, err
	}
	if r.Inventoried == nil {
		return protocol.HostConnectorInventoryMutationResponse{}, errors.New("connectorhost: expected inventory response")
	}
	response := *r.Inventoried
	if err := protocol.ValidateHostConnectorInventoryMutationResponse(response); err != nil {
		return response, err
	}
	if response.InstallationID != request.InstallationID || response.AcknowledgedRevision != request.Revision || (request.Kind == protocol.HostConnectorMutationRemove && len(response.StorageOrigins) != 0) {
		return response, errors.New("connectorhost: mismatched inventory acknowledgement")
	}
	return response, nil
}

func (c *ControlClient) Demand(ctx context.Context, capacity int) (*protocol.HostWork, error) {
	r, err := c.call(ctx, protocol.HostMessage{Demand: &protocol.HostDemand{ConnectorCapacity: capacity}})
	if err == nil && r.Work == nil && r.Ack == nil {
		err = errors.New("connectorhost: expected work response")
	}
	return r.Work, err
}

func (c *ControlClient) ack(ctx context.Context, request protocol.HostMessage) error {
	r, err := c.call(ctx, request)
	if err == nil && r.Ack == nil {
		return errors.New("connectorhost: expected durable acknowledgement")
	}
	return err
}

func (c *ControlClient) Heartbeat(ctx context.Context, request protocol.HostHeartbeat) error {
	return c.ack(ctx, protocol.HostMessage{Heartbeat: &request})
}
func (c *ControlClient) ConnectorEvent(ctx context.Context, connectorID, jobID string, event protocol.JobEvent) error {
	return c.ack(ctx, protocol.HostMessage{ConnectorEvent: &protocol.HostConnectorEvent{ConnectorID: connectorID, JobID: jobID, Event: event}})
}
func (c *ControlClient) ConnectorCompletion(ctx context.Context, connectorID, jobID string, completion protocol.JobCompletion) error {
	return c.ack(ctx, protocol.HostMessage{ConnectorCompletion: &protocol.HostConnectorCompletion{ConnectorID: connectorID, JobID: jobID, Completion: completion}})
}
func (c *ControlClient) ManagementEvent(ctx context.Context, jobID string, event protocol.HostManagementEvent) error {
	return c.ack(ctx, protocol.HostMessage{ManagementEvent: &protocol.HostManagementProgress{JobID: jobID, Event: event}})
}
func (c *ControlClient) ManagementCompletion(ctx context.Context, completion protocol.HostManagementCompletion) error {
	return c.ack(ctx, protocol.HostMessage{ManagementCompletion: &completion})
}
