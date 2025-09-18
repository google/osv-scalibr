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

package openrouter

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles"
)

const (
	// OpenRouter API base URL
	openRouterAPIBaseURL = "https://openrouter.ai/api"
	// Timeout for API validation requests
	validationTimeout = 10 * time.Second
)

// ValidationConfig holds configuration for API validation
type ValidationConfig struct {
	HTTPClient       *http.Client
	OpenRouterAPIURL string
}

// NewValidationConfig creates a new ValidationConfig with default values
func NewValidationConfig() *ValidationConfig {
	return &ValidationConfig{
		HTTPClient: &http.Client{
			Timeout: validationTimeout,
		},
		OpenRouterAPIURL: openRouterAPIBaseURL,
	}
}

// WithHTTPClient configures the http.Client for validation
func (c *ValidationConfig) WithHTTPClient(
	client *http.Client) *ValidationConfig {
	c.HTTPClient = client
	return c
}

// WithAPIURL configures the OpenRouter API URL for validation
func (c *ValidationConfig) WithAPIURL(url string) *ValidationConfig {
	c.OpenRouterAPIURL = url
	return c
}

var _ veles.Validator[APIKey] = &APIKeyValidator{}

// APIKeyValidator is a Veles Validator for OpenRouter API keys.
// It validates API keys by making a test request to the OpenRouter API.
type APIKeyValidator struct {
	config *ValidationConfig
}

// ValidatorOption configures an APIKeyValidator when creating it via
// NewAPIKeyValidator.
type ValidatorOption func(*APIKeyValidator)

// WithHTTPClient configures the http.Client that the APIKeyValidator uses.
//
// By default it uses http.DefaultClient with a timeout.
func WithHTTPClient(c *http.Client) ValidatorOption {
	return func(v *APIKeyValidator) {
		v.config.WithHTTPClient(c)
	}
}

// WithAPIURL configures the OpenRouter API URL that the APIKeyValidator uses.
//
// By default it uses the production OpenRouter API URL.
// This is useful for testing with mock servers.
func WithAPIURL(url string) ValidatorOption {
	return func(v *APIKeyValidator) {
		v.config.WithAPIURL(url)
	}
}

// NewAPIKeyValidator creates a new APIKeyValidator with the given
// ValidatorOptions.
func NewAPIKeyValidator(opts ...ValidatorOption) *APIKeyValidator {
	v := &APIKeyValidator{
		config: NewValidationConfig(),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given APIKey is valid.
//
// It makes a request to the /v1/auth/key endpoint which is specifically
// designed for API key validation and authentication checking.
func (v *APIKeyValidator) Validate(ctx context.Context,
	key APIKey) (veles.ValidationStatus, error) {
	// Check for empty key
	if key.Key == "" {
		return veles.ValidationFailed, errors.New("empty API key")
	}

	// Create HTTP request to the /v1/auth/key endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		v.config.OpenRouterAPIURL+"/v1/auth/key", nil)
	if err != nil {
		return veles.ValidationFailed,
			fmt.Errorf("unable to create HTTP request: %w", err)
	}

	// Set Authorization header with Bearer token (OpenRouter format)
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
		// authenticates against the OpenRouter API and that this account
		// is rate limited: https://openrouter.ai/docs/api-reference/errors
		return veles.ValidationValid, nil
	default:
		// Other status codes indicate an error in our validation process
		return veles.ValidationFailed,
			fmt.Errorf("unexpected HTTP status %d during validation",
				res.StatusCode)
	}
}
