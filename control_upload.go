package connectorhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

const maxControlUploadOverhead = 128 << 10

func writeControlUploadResult(ctx context.Context, w http.ResponseWriter, request *http.Request, host *Host, update bool) {
	request.Body = http.MaxBytesReader(w, request.Body, maxArtifactBytes+maxControlBodyBytes+maxControlUploadOverhead)
	reader, err := request.MultipartReader()
	if err != nil {
		writeControlError(w, http.StatusUnsupportedMediaType, "connectorhost: connector upload requires multipart/form-data")
		return
	}
	metadataPart, err := reader.NextPart()
	if err != nil || metadataPart.FormName() != "metadata" || metadataPart.FileName() != "" {
		writeControlError(w, http.StatusBadRequest, "connectorhost: connector upload must start with metadata")
		return
	}
	metadata, err := io.ReadAll(io.LimitReader(metadataPart, maxControlBodyBytes+1))
	_ = metadataPart.Close()
	if err != nil || len(metadata) > maxControlBodyBytes {
		writeControlError(w, http.StatusBadRequest, "connectorhost: connector upload metadata exceeds its size limit")
		return
	}
	artifactPart, err := reader.NextPart()
	if err != nil || artifactPart.FormName() != "artifact" || artifactPart.FileName() == "" {
		writeControlError(w, http.StatusBadRequest, "connectorhost: connector upload metadata must be followed by an artifact")
		return
	}
	filename := filepath.Base(artifactPart.FileName())
	if err := validateArtifactFilename(filename); err != nil {
		writeControlError(w, http.StatusBadRequest, err.Error())
		return
	}
	uploadDirectory, err := os.MkdirTemp(host.store.root, ".upload-")
	if err != nil {
		writeControlError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer os.RemoveAll(uploadDirectory)
	if err := secureDirectory(uploadDirectory); err != nil {
		writeControlError(w, http.StatusInternalServerError, err.Error())
		return
	}
	uploadPath := filepath.Join(uploadDirectory, filename)
	file, err := os.OpenFile(uploadPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		writeControlError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := secureFile(uploadPath); err != nil {
		_ = file.Close()
		writeControlError(w, http.StatusInternalServerError, err.Error())
		return
	}
	written, copyErr := io.Copy(file, io.LimitReader(artifactPart, maxArtifactBytes+1))
	closeErr := file.Close()
	_ = artifactPart.Close()
	if copyErr != nil || closeErr != nil {
		writeControlError(w, http.StatusBadRequest, errors.Join(copyErr, closeErr).Error())
		return
	}
	if written < 1 || written > maxArtifactBytes {
		writeControlError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("connectorhost: artifact size must be between 1 and %d bytes", maxArtifactBytes))
		return
	}
	if extra, err := reader.NextPart(); err == nil || !errors.Is(err, io.EOF) {
		if extra != nil {
			_ = extra.Close()
		}
		writeControlError(w, http.StatusBadRequest, "connectorhost: connector upload contains unexpected extra parts")
		return
	}
	if update {
		var input LocalUpdateRequest
		if err := strictJSON(metadata, &input); err != nil || input.SourcePath != "" || input.ArtifactSize != written {
			writeControlError(w, http.StatusBadRequest, "connectorhost: invalid connector update upload metadata")
			return
		}
		input.SourcePath = uploadPath
		writeControlResult(w, struct{}{}, host.LocalUpdate(ctx, input))
		return
	}
	var input LocalInstallRequest
	if err := strictJSON(metadata, &input); err != nil || input.SourcePath != "" || input.ArtifactSize != written {
		writeControlError(w, http.StatusBadRequest, "connectorhost: invalid connector install upload metadata")
		return
	}
	input.SourcePath = uploadPath
	result, err := host.LocalInstall(ctx, input)
	writeControlResult(w, result, err)
}

func (c *LocalControlClient) InstallFile(ctx context.Context, request LocalInstallRequest) (LocalInstallResponse, error) {
	var response LocalInstallResponse
	err := c.upload(ctx, "/v1/connectors/install-upload", request.SourcePath, request, &response)
	return response, err
}

func (c *LocalControlClient) UpdateFile(ctx context.Context, request LocalUpdateRequest) error {
	return c.upload(ctx, "/v1/connectors/update-upload", request.SourcePath, request, nil)
}

func (c *LocalControlClient) upload(ctx context.Context, endpoint, sourcePath string, metadata, output any) error {
	file, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxArtifactBytes {
		return fmt.Errorf("connectorhost: artifact size must be between 1 and %d bytes", maxArtifactBytes)
	}
	metadataBody, err := json.Marshal(metadataForUpload(metadata, info.Size()))
	if err != nil {
		return err
	}
	pipeReader, pipeWriter := io.Pipe()
	multipartWriter := multipart.NewWriter(pipeWriter)
	writeResult := make(chan error, 1)
	go func() {
		var writeErr error
		part, err := multipartWriter.CreateFormField("metadata")
		if err == nil {
			_, err = part.Write(metadataBody)
		}
		if err == nil {
			part, err = multipartWriter.CreateFormFile("artifact", filepath.Base(sourcePath))
		}
		if err == nil {
			_, err = io.Copy(part, file)
		}
		writeErr = errors.Join(err, multipartWriter.Close())
		_ = pipeWriter.CloseWithError(writeErr)
		writeResult <- writeErr
	}()
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+endpoint, pipeReader)
	if err != nil {
		_ = pipeReader.Close()
		return err
	}
	httpRequest.Header.Set("Authorization", "Bearer "+c.token)
	httpRequest.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	response, requestErr := c.http.Do(httpRequest)
	if requestErr != nil {
		_ = pipeReader.CloseWithError(requestErr)
		<-writeResult
		return requestErr
	}
	defer response.Body.Close()
	mediaType := response.Header.Get("Content-Type")
	mediaType = string(bytes.TrimSpace([]byte(mediaType)))
	if separator := bytes.IndexByte([]byte(mediaType), ';'); separator >= 0 {
		mediaType = mediaType[:separator]
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxControlReplyBytes+1))
	writeErr := <-writeResult
	if readErr != nil {
		return readErr
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var failure controlError
		if mediaType != "application/json" || strictJSON(body, &failure) != nil || failure.Error == "" {
			failure.Error = fmt.Sprintf("connectorhost: local control returned HTTP %d", response.StatusCode)
		}
		return &LocalControlAPIError{Status: response.StatusCode, Text: failure.Error}
	}
	if writeErr != nil {
		return writeErr
	}
	if len(body) > maxControlReplyBytes {
		return errors.New("connectorhost: local control response exceeds size limit")
	}
	if output == nil {
		return nil
	}
	return strictJSON(body, output)
}

func metadataForUpload(metadata any, size int64) any {
	switch input := metadata.(type) {
	case LocalInstallRequest:
		input.SourcePath = ""
		input.ArtifactSize = size
		return input
	case LocalUpdateRequest:
		input.SourcePath = ""
		input.ArtifactSize = size
		return input
	default:
		panic("connectorhost: unsupported connector upload metadata")
	}
}
