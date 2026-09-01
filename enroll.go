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

type EnrollmentPrompt struct {
	VerificationURL string    `json:"verificationUrl"`
	UserCode        string    `json:"userCode"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

func Enroll(ctx context.Context, store *Store, baseURL string, mode AccessMode, output io.Writer) error {
	return EnrollWithPrompt(ctx, store, baseURL, mode, http.DefaultClient, func(prompt EnrollmentPrompt) error {
		_, err := fmt.Fprintf(output, "Open: %s\nCode: %s\n", prompt.VerificationURL, prompt.UserCode)
		return err
	})
}

func EnrollWithPrompt(ctx context.Context, store *Store, baseURL string, mode AccessMode, httpClient *http.Client, prompt func(EnrollmentPrompt) error) error {
	if store == nil {
		panic("connectorhost: enrollment store is required")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if prompt == nil {
		panic("connectorhost: enrollment prompt callback is required")
	}
	if _, err := ParseAccessMode(string(mode)); err != nil {
		return err
	}
	baseURL, err := normalizeAirlockOrigin(baseURL)
	if err != nil {
		return err
	}
	client := *httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	name, _ := os.Hostname()
	request := protocol.HostInfo{ProtocolVersion: protocol.HostProtocolVersion, Name: name, Platform: runtime.GOOS, Architecture: platformArchitecture(), AccessMode: mode, Version: Version}
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
	if err := prompt(EnrollmentPrompt{VerificationURL: device.VerificationURL, UserCode: device.UserCode, ExpiresAt: device.ExpiresAt}); err != nil {
		return err
	}
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
			return store.SetEnrollment(baseURL, response.Credential, response.HostID, mode)
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

func ValidateAirlockOrigin(baseURL string) error {
	_, err := normalizeAirlockOrigin(baseURL)
	return err
}

func normalizeAirlockOrigin(baseURL string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("connectorhost: Airlock URL must be an HTTPS origin")
	}
	return strings.TrimSuffix(baseURL, "/"), nil
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
