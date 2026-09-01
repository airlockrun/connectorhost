package connectorhost

import (
	"net/http"
	"time"
)

func noProxyHTTPClient(client *http.Client, timeout time.Duration) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	copy := *client
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if configured, ok := client.Transport.(*http.Transport); ok {
		transport = configured.Clone()
	}
	transport.Proxy = nil
	copy.Transport = transport
	copy.Timeout = timeout
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &copy
}
