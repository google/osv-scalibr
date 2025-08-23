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

// ValidationConfig holds configuration for API validation
type ValidationConfig struct {
	HTTPClient      *http.Client
	AnthropicAPIURL string
}

// NewValidationConfig creates a new ValidationConfig with default values
func NewValidationConfig() *ValidationConfig {
	return &ValidationConfig{
		HTTPClient: &http.Client{
			Timeout: validationTimeout,
		},
		AnthropicAPIURL: anthropicAPIBaseURL,
	}
}

// WithHTTPClient configures the http.Client for validation
func (c *ValidationConfig) WithHTTPClient(client *http.Client) *ValidationConfig {
	c.HTTPClient = client
	return c
}

// WithAPIURL configures the Anthropic API URL for validation
func (c *ValidationConfig) WithAPIURL(url string) *ValidationConfig {
	c.AnthropicAPIURL = url
	return c
}

// validateAPIKey performs the actual API validation for a given key and endpoint
func validateAPIKey(ctx context.Context, config *ValidationConfig, key string, endpoint string) (veles.ValidationStatus, error) {
	// Check for empty key
	if key == "" {
		return veles.ValidationFailed, errors.New("empty API key")
	}

	// Create HTTP request to the specified endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, config.AnthropicAPIURL+endpoint, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}

	// Set headers (no Content-Type needed for GET request)
	req.Header.Set("X-Api-Key", key)
	req.Header.Set("Anthropic-Version", anthropicAPIVersion)

	// Make the request
	res, err := config.HTTPClient.Do(req)
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
	case http.StatusTooManyRequests:
		// Rate limited - key is likely valid but we're being throttled.
		// StatusTooManyRequests indicates that the key successfully authenticates
		// against the Anthropic API and that this account is rate limited.
		return veles.ValidationValid, nil
	default:
		// Other status codes indicate an error in our validation process
		return veles.ValidationFailed, fmt.Errorf("unexpected HTTP status %d during validation", res.StatusCode)
	}
}
