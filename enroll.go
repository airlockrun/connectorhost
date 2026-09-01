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
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

type hostDeviceCodeResponse struct {
	DeviceSecret        string    `json:"deviceSecret"`
	UserCode            string    `json:"userCode"`
	VerificationURL     string    `json:"verificationUrl"`
	ExpiresAt           time.Time `json:"expiresAt"`
	PollIntervalSeconds int       `json:"pollIntervalSeconds"`
}

type hostEnrollmentResponse struct {
	Status     string `json:"status"`
	HostID     string `json:"hostId,omitempty"`
	Credential string `json:"credential,omitempty"`
	Error      string `json:"error,omitempty"`
}

func Enroll(ctx context.Context, store *Store, baseURL string, output io.Writer) error {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("connectorhost: Airlock URL must be an HTTPS origin")
	}
	baseURL = strings.TrimSuffix(baseURL, "/")
	client := *http.DefaultClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	name, _ := os.Hostname()
	request := protocol.HostInfo{ProtocolVersion: protocol.HostProtocolVersion, Name: name, Platform: runtime.GOOS, Architecture: platformArchitecture(), AccessMode: store.AccessMode(), Version: Version}
	var device hostDeviceCodeResponse
	if err := enrollmentPost(ctx, &client, baseURL+"/api/hosts/v1/enroll/device-code", request, &device); err != nil {
		return err
	}
	if device.DeviceSecret == "" || device.UserCode == "" || !device.ExpiresAt.After(time.Now()) || device.PollIntervalSeconds < 1 {
		return errors.New("connectorhost: Airlock returned invalid enrollment data")
	}
	verification, err := url.Parse(device.VerificationURL)
	if err != nil || verification.User != nil || strings.ToLower(verification.Scheme+"://"+verification.Host) != strings.ToLower(baseURL) {
		return errors.New("connectorhost: verification URL does not use the exact Airlock origin")
	}
	_, _ = fmt.Fprintf(output, "Open: %s\nCode: %s\n", device.VerificationURL, device.UserCode)
	interval := time.Duration(device.PollIntervalSeconds) * time.Second
	for {
		if !device.ExpiresAt.After(time.Now()) {
			return errors.New("connectorhost: enrollment expired")
		}
		var response hostEnrollmentResponse
		if err := enrollmentPost(ctx, &client, baseURL+"/api/hosts/v1/enroll/complete", struct {
			DeviceSecret string `json:"deviceSecret"`
		}{device.DeviceSecret}, &response); err != nil {
			return err
		}
		switch response.Status {
		case "approved":
			if response.HostID == "" || response.Credential == "" {
				return errors.New("connectorhost: approved enrollment omitted host credentials")
			}
			return store.SetCredentials(baseURL, response.Credential, response.HostID)
		case "pending":
		case "denied":
			return errors.New("connectorhost: enrollment denied")
		case "expired":
			return errors.New("connectorhost: enrollment expired")
		default:
			return fmt.Errorf("connectorhost: unknown enrollment status %q", response.Status)
		}
		if err := sleepContext(ctx, interval); err != nil {
			return err
		}
	}
}

func enrollmentPost(ctx context.Context, client *http.Client, endpoint string, input, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("connectorhost: enrollment returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, protocol.MaxEnvelopeBytes+1))
	if err != nil {
		return err
	}
	if len(data) > protocol.MaxEnvelopeBytes {
		return errors.New("connectorhost: enrollment response exceeds size limit")
	}
	return strictJSON(data, output)
}
