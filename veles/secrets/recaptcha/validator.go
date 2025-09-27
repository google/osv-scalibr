// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package recaptcha

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/osv-scalibr/veles"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Validator[CaptchaSecret] = &Validator{}
)

const (
	validationEndpoint = "https://www.google.com/recaptcha/api/siteverify"
)

// Validator validates reCAPTCHA secret keys.
type Validator struct {
	httpC *http.Client
}

// ValidatorOption configures a Validator when creating it via New.
type ValidatorOption func(*Validator)

// WithClient configures the http.Client used by the Validator.
// By default it uses http.DefaultClient.
func WithClient(c *http.Client) ValidatorOption {
	return func(v *Validator) {
		v.httpC = c
	}
}

// NewValidator creates a new Validator with the given options.
func NewValidator(opts ...ValidatorOption) *Validator {
	v := &Validator{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

type validationResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
}

// Validate checks whether the given CaptchaSecret is valid by sending a request to Google's reCAPTCHA API.
//
// Validation logic is based on https://developers.google.com/recaptcha/docs/verify
// Validation steps:
// 1. Sends a POST request with the secret and a dummy response value.
// 2. If the API response 'success' is true, the secret is valid.
// 3. If 'invalid-input-response' is present in error codes, the secret is valid (dummy response is expected to fail).
// 4. If 'invalid-input-secret' is present, the secret is invalid.
// 5. Any other error or unexpected response results in validation failure.
func (v *Validator) Validate(ctx context.Context, secret CaptchaSecret) (veles.ValidationStatus, error) {
	// Prepare POST data with secret and dummy response
	data := url.Values{}
	data.Set("secret", secret.Key)
	data.Set("response", "ffffffffffffffffffffffffffffffffffffffffffffffff")

	// Create HTTP request to reCAPTCHA API
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, validationEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		// Request creation failed
		return veles.ValidationFailed, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Send the request
	resp, err := v.httpC.Do(req)
	if err != nil {
		// Network or client error
		return veles.ValidationFailed, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Check for successful HTTP response
	if resp.StatusCode != http.StatusOK {
		// Unexpected HTTP status
		return veles.ValidationFailed, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the JSON response from the API
	var validationResp validationResponse
	if err := json.NewDecoder(resp.Body).Decode(&validationResp); err != nil {
		// Failed to decode JSON
		return veles.ValidationFailed, fmt.Errorf("failed to decode response: %w", err)
	}

	// Step 1: If success is true, the secret is valid
	if validationResp.Success {
		return veles.ValidationValid, nil
	}

	// Step 2: Check error codes for specific validation outcomes
	for _, errCode := range validationResp.ErrorCodes {
		// If the response is invalid, but the secret is valid
		if errCode == "invalid-input-response" {
			return veles.ValidationValid, nil
		}
		// If the secret itself is invalid
		if errCode == "invalid-input-secret" {
			return veles.ValidationInvalid, nil
		}
	}

	// Step 3: Any other error codes are treated as validation failure
	return veles.ValidationFailed, fmt.Errorf("unexpected error codes: %v", validationResp.ErrorCodes)
}
