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

package anthropicapikey

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/osv-scalibr/veles"
)

const (
	// Anthropic API base URL
	anthropicAPIBaseURL = "https://api.anthropic.com"
	// Anthropic API version header
	anthropicAPIVersion = "2023-06-01"
	// Timeout for API validation requests
	validationTimeout = 10 * time.Second
)

var _ veles.Validator[AnthropicAPIKey] = &Validator{}

// Validator is a Veles Validator for Anthropic API keys.
// It validates API keys by making a test request to the Anthropic API.
type Validator struct {
	httpC           *http.Client
	anthropicAPIURL string
}

// ValidatorOption configures a Validator when creating it via NewValidator.
type ValidatorOption func(*Validator)

// WithClient configures the http.Client that the Validator uses.
//
// By default it uses http.DefaultClient with a timeout.
func WithClient(c *http.Client) ValidatorOption {
	return func(v *Validator) {
		v.httpC = c
	}
}

// WithAPIURL configures the Anthropic API URL that the Validator uses.
//
// By default it uses the production Anthropic API URL.
// This is useful for testing with mock servers.
func WithAPIURL(url string) ValidatorOption {
	return func(v *Validator) {
		v.anthropicAPIURL = url
	}
}

// NewValidator creates a new Validator with the given ValidatorOptions.
func NewValidator(opts ...ValidatorOption) *Validator {
	v := &Validator{
		httpC: &http.Client{
			Timeout: validationTimeout,
		},
		anthropicAPIURL: anthropicAPIBaseURL,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given AnthropicAPIKey is valid.
//
// It makes a request to different Anthropic API endpoints based on the key type:
// - Admin keys (containing "admin01"): Uses /v1/organizations/workspaces endpoint
// - Regular API keys: Uses /v1/models endpoint
// Both endpoints don't consume tokens and are used for validation purposes.
func (v *Validator) Validate(ctx context.Context, key AnthropicAPIKey) (veles.ValidationStatus, error) {
	// Check for empty key
	if key.Key == "" {
		return veles.ValidationFailed, errors.New("empty API key")
	}

	// Determine endpoint based on key type
	var endpoint string
	if strings.Contains(key.Key, "admin01") {
		// Admin keys use the organizations/workspaces endpoint
		endpoint = "/v1/organizations/workspaces"
	} else {
		// Regular API keys use the models endpoint
		endpoint = "/v1/models"
	}

	// Create HTTP request to the appropriate endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.anthropicAPIURL+endpoint, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}

	// Set headers (no Content-Type needed for GET request)
	req.Header.Set("X-Api-Key", key.Key)
	req.Header.Set("Anthropic-Version", anthropicAPIVersion)

	// Make the request
	res, err := v.httpC.Do(req)
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
	case http.StatusForbidden:
		// Key might be valid but lacks permissions, or rate limited
		// For validation purposes, we'll consider this as potentially valid
		return veles.ValidationValid, nil
	case http.StatusTooManyRequests:
		// Rate limited - key is likely valid but we're being throttled
		return veles.ValidationValid, nil
	default:
		// Other status codes indicate an error in our validation process
		return veles.ValidationFailed, fmt.Errorf("unexpected HTTP status %d during validation", res.StatusCode)
	}
}
