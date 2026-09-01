package connectorhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

func strictJSON(body []byte, result any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(result); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("connectorhost: trailing JSON")
	}
	return nil
}
