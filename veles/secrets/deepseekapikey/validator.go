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

package deepseekapikey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles"
)

const (
	// DeepSeek API base URL
	deepseekAPIBaseURL = "https://api.deepseek.com"
	// Timeout for API validation requests
	validationTimeout = 10 * time.Second
)

// ValidationConfig holds configuration for API validation
type ValidationConfig struct {
	HTTPClient     *http.Client
	DeepSeekAPIURL string
}

// NewValidationConfig creates a new ValidationConfig with default values
func NewValidationConfig() *ValidationConfig {
	return &ValidationConfig{
		HTTPClient: &http.Client{
			Timeout: validationTimeout,
		},
		DeepSeekAPIURL: deepseekAPIBaseURL,
	}
}

// WithHTTPClient configures the http.Client for validation
func (c *ValidationConfig) WithHTTPClient(client *http.Client) *ValidationConfig {
	c.HTTPClient = client
	return c
}

// WithAPIURL configures the DeepSeek API URL for validation
func (c *ValidationConfig) WithAPIURL(url string) *ValidationConfig {
	c.DeepSeekAPIURL = url
	return c
}

var _ veles.Validator[APIKey] = &APIValidator{}

// APIValidator is a Veles Validator for DeepSeek API keys.
// It validates API keys by making a test request to the DeepSeek API.
type APIValidator struct {
	config *ValidationConfig
}

// APIValidatorOption configures an APIValidator when creating it via
// NewAPIValidator.
type APIValidatorOption func(*APIValidator)

// WithHTTPClient configures the http.Client that the APIValidator uses.
// By default it uses http.DefaultClient with a timeout.
func WithHTTPClient(c *http.Client) APIValidatorOption {
	return func(v *APIValidator) {
		v.config.WithHTTPClient(c)
	}
}

// WithAPIURL configures the DeepSeek API URL that the APIValidator uses.
// By default it uses the production DeepSeek API URL.
// This is useful for testing with mock servers.
func WithAPIURL(url string) APIValidatorOption {
	return func(v *APIValidator) {
		v.config.WithAPIURL(url)
	}
}

// NewAPIValidator creates a new APIValidator with the given APIValidatorOptions.
func NewAPIValidator(opts ...APIValidatorOption) *APIValidator {
	v := &APIValidator{
		config: NewValidationConfig(),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// testRequest represents the JSON payload for the DeepSeek API test request
type testRequest struct {
	Model    string    `json:"model"`
	Messages []message `json:"messages"`
	Stream   bool      `json:"stream"`
}

// message represents a chat message in the DeepSeek API request
type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Validate checks whether the given APIKey is valid.
// It makes a request to the /chat/completions endpoint with a minimal test payload.
func (v *APIValidator) Validate(ctx context.Context, key APIKey) (veles.ValidationStatus, error) {
	// Check for empty key
	if key.Key == "" {
		return veles.ValidationFailed, errors.New("empty API key")
	}

	// Create the test request payload
	payload := testRequest{
		Model: "deepseek-chat",
		Messages: []message{
			{Role: "system", Content: "You are a helpful assistant."},
			{Role: "user", Content: "Hello!"},
		},
		Stream: false,
	}

	// Marshal the JSON payload
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to marshal JSON payload: %w", err)
	}

	// Create HTTP request to the /chat/completions endpoint
	endpoint := v.config.DeepSeekAPIURL + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}

	// Set required headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key.Key)

	// Make the request
	res, err := v.config.HTTPClient.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to validate API key: %w", err)
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
	case http.StatusPaymentRequired:
		// API key is valid but billing/quota issues - key exists and is
		// authenticated
		return veles.ValidationValid, nil
	case http.StatusTooManyRequests:
		// Rate limited - key is likely valid but we're being throttled
		return veles.ValidationValid, nil
	case http.StatusForbidden:
		// API key might be valid but doesn't have permission for this
		// endpoint
		return veles.ValidationValid, nil
	default:
		// Other status codes indicate an error in our validation process
		return veles.ValidationFailed,
			fmt.Errorf("unexpected HTTP status %d during validation",
				res.StatusCode)
	}
}
