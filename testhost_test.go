package connectorhost

import (
	"io"
	"log/slog"
	"net/http"
)

func newTestHost(store *Store, client *http.Client) *Host {
	return NewHost(store, client, slog.New(slog.NewTextHandler(io.Discard, nil)))
}
