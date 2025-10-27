// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pypiapitoken

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/http"

	"github.com/google/osv-scalibr/veles"
)

// Validator validates PyPI API Tokens via the PyPI API endpoint.
type Validator struct {
	httpC *http.Client
}

// ValidatorOption configures a Validator when creating it via NewValidator.
type ValidatorOption func(*Validator)

// WithClient configures the http.Client that the Validator uses.
//
// By default, it uses http.DefaultClient.
func WithClient(c *http.Client) ValidatorOption {
	return func(v *Validator) {
		v.httpC = c
	}
}

// NewValidator creates a new Validator with the given ValidatorOptions.
func NewValidator(opts ...ValidatorOption) *Validator {
	v := &Validator{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given PyPIAPIToken is valid.
//
// It performs a POST request to the PyPI legacy upload URL with multipart form data
// using the API token in the Authorization header. If the request returns
// HTTP 400 Bad Request, the key is considered valid.
// If HTTP 403 Forbidden, the key is considered invalid.
// Other errors return ValidationFailed.
// We send an invalid package to don't add any new package to the account.
func (v *Validator) Validate(ctx context.Context, key PyPIAPIToken) (veles.ValidationStatus, error) {
	// Create a buffer for the multipart form data
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	// Add form fields
	if err := writer.WriteField(":action", "file_upload"); err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to add :action field: %w", err)
	}
	if err := writer.WriteField("name", "dummy-package"); err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to add name field: %w", err)
	}
	if err := writer.WriteField("version", "0.0.1"); err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to add version field: %w", err)
	}
	if err := writer.WriteField("content", "dummy-content"); err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to add content field: %w", err)
	}

	// Close the writer to finalize the form
	if err := writer.Close(); err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to close multipart writer: %w", err)
	}

	// Create a new POST request to the PyPI legacy upload URL
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://upload.pypi.org/legacy/", &body)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}

	// Add the Authorization header with the PyPI API token
	req.Header.Set("Authorization", "token "+key.Token)
	// Set the Content-Type to the multipart form boundary
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Execute the HTTP request
	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("HTTP POST failed: %w", err)
	}
	defer res.Body.Close()

	// Check status codes for validation
	switch res.StatusCode {
	case http.StatusBadRequest:
		return veles.ValidationValid, nil
	case http.StatusForbidden:
		return veles.ValidationInvalid, nil
	default:
		return veles.ValidationFailed, nil
	}
}
