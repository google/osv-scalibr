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

package gcpoauth2token

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/osv-scalibr/veles"
)

// tokenInfoResponse represents the response from Google's tokeninfo endpoint.
type tokenInfoResponse struct {
	Audience         string `json:"audience,omitempty"`
	Scope            string `json:"scope,omitempty"`
	UserID           string `json:"user_id,omitempty"`
	ExpiresIn        string `json:"expires_in,omitempty"`
	Email            string `json:"email,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// Validator implements veles.Validator for GCP OAuth2 access tokens.
type Validator struct {
	client *http.Client
}

// NewValidator creates a new Validator for GCP OAuth2 access tokens.
func NewValidator() veles.Validator[GCPOAuth2AccessToken] {
	return &Validator{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Validate checks if a GCP OAuth2 access token is valid by calling Google's tokeninfo endpoint.
func (v *Validator) Validate(ctx context.Context, token GCPOAuth2AccessToken) (veles.ValidationStatus, error) {
	if token.Token == "" {
		return veles.ValidationFailed, errors.New("empty token")
	}

	// Validate using Google's tokeninfo endpoint
	tokenInfoURL := "https://www.googleapis.com/oauth2/v1/tokeninfo"
	params := url.Values{}
	params.Set("access_token", token.Token)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenInfoURL+"?"+params.Encode(), nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to validate token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to read response: %w", err)
	}

	var tokenInfo tokenInfoResponse
	if err := json.Unmarshal(body, &tokenInfo); err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for error in response
	if tokenInfo.Error != "" {
		// Common errors: "invalid_token", "expired_token"
		if tokenInfo.Error == "invalid_token" {
			return veles.ValidationInvalid, nil
		}
		return veles.ValidationFailed, fmt.Errorf("token validation error: %s - %s", tokenInfo.Error, tokenInfo.ErrorDescription)
	}

	// Token is valid if we have scope or audience information
	if tokenInfo.Scope != "" || tokenInfo.Audience != "" {
		return veles.ValidationValid, nil
	}

	return veles.ValidationFailed, errors.New("unexpected response format")
}
