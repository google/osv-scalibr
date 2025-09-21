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

package slacktoken

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/osv-scalibr/veles"
)

// Validator validates Slack App tokens via the Slack API endpoint.
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

// Validate checks whether the given SlackToken is valid.
//
// It supports three types of Slack tokens:
// 1. App Level Token (IsAppLevelToken) - uses auth.test endpoint
// 2. App Configuration Access Token (IsAppConfigAccessToken) - uses auth.test endpoint
// 3. App Configuration Refresh Token (IsAppConfigRefreshToken) - uses tooling.tokens.rotate endpoint
//
// Each token type has different validation endpoints and response formats.
func (v *Validator) Validate(ctx context.Context, key SlackToken) (veles.ValidationStatus, error) {
	if key.IsAppLevelToken || key.IsAppConfigAccessToken {
		return v.validateAuthToken(ctx, key.Token)
	}
	if key.IsAppConfigRefreshToken {
		return v.validateRefreshToken(ctx, key.Token)
	}

	return veles.ValidationInvalid, nil
}

// validateAuthToken validates tokens using the auth.test endpoint.
// This function handles both App Level Tokens (xapp-) and App Configuration Access Tokens (xoxe.xoxp-)
// since both token types use the same Slack API endpoint for validation.
func (v *Validator) validateAuthToken(ctx context.Context, token string) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://slack.com/api/auth.test", nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("HTTP POST failed: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse JSON response
	var response struct {
		Ok    bool   `json:"ok"`
		Error string `json:"error"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	if response.Ok {
		return veles.ValidationValid, nil
	} else if response.Error == "invalid_auth" {
		return veles.ValidationInvalid, nil
	}
	return veles.ValidationFailed, nil
}


// validateRefreshToken validates App Configuration Refresh Tokens (xoxe-)
func (v *Validator) validateRefreshToken(ctx context.Context, token string) (veles.ValidationStatus, error) {
	// Prepare form data
	formData := url.Values{}
	formData.Set("refresh_token", token)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://slack.com/api/tooling.tokens.rotate", strings.NewReader(formData.Encode()))
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("HTTP POST failed: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse JSON response
	var response struct {
		Ok    bool   `json:"ok"`
		Error string `json:"error"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	if response.Ok {
		return veles.ValidationValid, nil
	} else if response.Error == "invalid_refresh_token" {
		return veles.ValidationInvalid, nil
	}
	return veles.ValidationFailed, nil
}
