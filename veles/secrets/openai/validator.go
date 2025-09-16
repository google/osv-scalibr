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

package openai

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles"
)

const (
	// OpenAI API base URL
	openaiAPIBaseURL = "https://api.openai.com"
	// Timeout for API validation requests
	validationTimeout = 10 * time.Second
)

// ValidationConfig holds configuration for API validation
type ValidationConfig struct {
	HTTPClient   *http.Client
	OpenAIAPIURL string
}

// NewValidationConfig creates a new ValidationConfig with default values
func NewValidationConfig() *ValidationConfig {
	return &ValidationConfig{
		HTTPClient: &http.Client{
			Timeout: validationTimeout,
		},
		OpenAIAPIURL: openaiAPIBaseURL,
	}
}

// WithHTTPClient configures the http.Client for validation
func (c *ValidationConfig) WithHTTPClient(
	client *http.Client) *ValidationConfig {
	c.HTTPClient = client
	return c
}

// WithAPIURL configures the OpenAI API URL for validation
func (c *ValidationConfig) WithAPIURL(url string) *ValidationConfig {
	c.OpenAIAPIURL = url
	return c
}

var _ veles.Validator[APIKey] = &ProjectValidator{}

// ProjectValidator is a Veles Validator for OpenAI API keys.
// It validates API keys by making a test request to the OpenAI API.
type ProjectValidator struct {
	config *ValidationConfig
}

// ProjectValidatorOption configures a ProjectValidator when creating it via
// NewProjectValidator.
type ProjectValidatorOption func(*ProjectValidator)

// WithProjectHTTPClient configures the http.Client that the ProjectValidator
// uses.
//
// By default it uses http.DefaultClient with a timeout.
func WithProjectHTTPClient(c *http.Client) ProjectValidatorOption {
	return func(v *ProjectValidator) {
		v.config.WithHTTPClient(c)
	}
}

// WithProjectAPIURL configures the OpenAI API URL that the ProjectValidator
// uses.
//
// By default it uses the production OpenAI API URL.
// This is useful for testing with mock servers.
func WithProjectAPIURL(url string) ProjectValidatorOption {
	return func(v *ProjectValidator) {
		v.config.WithAPIURL(url)
	}
}

// NewProjectValidator creates a new ProjectValidator with the given
// ProjectValidatorOptions.
func NewProjectValidator(opts ...ProjectValidatorOption) *ProjectValidator {
	v := &ProjectValidator{
		config: NewValidationConfig(),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given APIKey is valid.
//
// It makes a request to the /v1/models endpoint which is lightweight and
// doesn't consume tokens. This endpoint is used for validation purposes.
func (v *ProjectValidator) Validate(ctx context.Context,
	key APIKey) (veles.ValidationStatus, error) {
	// Check for empty key
	if key.Key == "" {
		return veles.ValidationFailed, errors.New("empty API key")
	}

	// Create HTTP request to the /v1/models endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		v.config.OpenAIAPIURL+"/v1/models", nil)
	if err != nil {
		return veles.ValidationFailed,
			fmt.Errorf("unable to create HTTP request: %w", err)
	}

	// Set Authorization header with Bearer token (OpenAI format)
	req.Header.Set("Authorization", "Bearer "+key.Key)

	// Make the request
	res, err := v.config.HTTPClient.Do(req)
	if err != nil {
		return veles.ValidationFailed,
			fmt.Errorf("unable to validate API key: %w", err)
	}
	defer res.Body.Close()

	// Check response status
	switch res.StatusCode {
	case http.StatusOK:
		// Key is valid
		return veles.ValidationValid, nil
	case http.StatusUnauthorized:
		// Key is invalid
		return veles.ValidationInvalid, nil
	case http.StatusTooManyRequests:
		// Rate limited - key is likely valid but we're being throttled.
		// StatusTooManyRequests indicates that the key successfully
		// authenticates against the OpenAI API and that this account
		// is rate limited.
		return veles.ValidationValid, nil
	default:
		// Other status codes indicate an error in our validation process
		return veles.ValidationFailed,
			fmt.Errorf("unexpected HTTP status %d during validation",
				res.StatusCode)
	}
}
