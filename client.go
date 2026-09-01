package connectorhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

type ControlClient struct {
	baseURL    string
	credential string
	http       *http.Client
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
	return &ControlClient{baseURL: strings.TrimSuffix(baseURL, "/"), credential: credential, http: &copy}, nil
}

func (c *ControlClient) Sync(ctx context.Context, request protocol.HostSyncRequest) (protocol.HostSyncResponse, error) {
	var response protocol.HostSyncResponse
	err := c.post(ctx, "/api/hosts/v1/sync", request, &response)
	return response, err
}

func (c *ControlClient) InventoryMutation(ctx context.Context, request protocol.HostConnectorInventoryMutationRequest) (protocol.HostConnectorInventoryMutationResponse, error) {
	var response protocol.HostConnectorInventoryMutationResponse
	if err := protocol.ValidateHostConnectorInventoryMutationRequest(request); err != nil {
		return response, err
	}
	if err := c.postBounded(ctx, "/api/hosts/v1/connectors/inventory", request, &response, protocol.MaxHostInventoryMutationBytes, 256<<10); err != nil {
		return response, err
	}
	if err := protocol.ValidateHostConnectorInventoryMutationResponse(response); err != nil {
		return response, err
	}
	if response.InstallationID != request.InstallationID || response.AcknowledgedRevision != request.Revision {
		return response, errors.New("connectorhost: inventory mutation response does not match its request")
	}
	if request.Kind == protocol.HostConnectorMutationRemove && len(response.StorageOrigins) != 0 {
		return response, errors.New("connectorhost: inventory removal acknowledgement includes storage origins")
	}
	return response, nil
}

func (c *ControlClient) Poll(ctx context.Context, request protocol.HostPollRequest) (protocol.HostPollResponse, error) {
	var response protocol.HostPollResponse
	err := c.post(ctx, "/api/hosts/v1/work/poll", request, &response)
	return response, err
}

func (c *ControlClient) ConnectorEvent(ctx context.Context, connectorID, jobID string, event protocol.JobEvent) error {
	return c.post(ctx, "/api/hosts/v1/connectors/"+url.PathEscape(connectorID)+"/jobs/"+url.PathEscape(jobID)+"/events", event, nil)
}

func (c *ControlClient) ConnectorCompletion(ctx context.Context, connectorID, jobID string, completion protocol.JobCompletion) error {
	return c.post(ctx, "/api/hosts/v1/connectors/"+url.PathEscape(connectorID)+"/jobs/"+url.PathEscape(jobID)+"/complete", completion, nil)
}

func (c *ControlClient) ManagementEvent(ctx context.Context, jobID string, event protocol.HostManagementEvent) error {
	return c.post(ctx, "/api/hosts/v1/management/"+url.PathEscape(jobID)+"/events", event, nil)
}

func (c *ControlClient) ManagementCompletion(ctx context.Context, completion protocol.HostManagementCompletion) error {
	return c.post(ctx, "/api/hosts/v1/management/"+url.PathEscape(completion.JobID)+"/complete", completion, nil)
}

func (c *ControlClient) post(ctx context.Context, endpoint string, input, output any) error {
	return c.postBounded(ctx, endpoint, input, output, protocol.MaxChildFrameBytes, protocol.MaxChildFrameBytes)
}

func (c *ControlClient) postBounded(ctx context.Context, endpoint string, input, output any, maxRequestBytes, maxResponseBytes int) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	if len(body) > maxRequestBytes {
		return errors.New("connectorhost: control request exceeds size limit")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.credential)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		return nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		return fmt.Errorf("connectorhost: POST %s returned HTTP %d: %s", endpoint, response.StatusCode, strings.TrimSpace(string(message)))
	}
	if output == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(maxResponseBytes)+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponseBytes {
		return errors.New("connectorhost: control response exceeds size limit")
	}
	return strictJSON(data, output)
}
