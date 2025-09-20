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
	"strconv"
	"time"

	"github.com/google/osv-scalibr/veles"
)

// tokenInfoResponse represents the response from Google's tokeninfo endpoint.
// https://developers.google.com/identity/protocols/oauth2
type tokenInfoResponse struct {
	// Expiry is the expiration time of the token in Unix time.
	Expiry string `json:"exp"`
	// ExpiresIn is the number of seconds until the token expires.
	ExpiresIn string `json:"expires_in"`
	// Scope is a space-delimited list that identify the resources that your application could access
	// https://developers.google.com/identity/protocols/oauth2/scopes
	Scope string `json:"scope"`
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
	tokenInfoURL := "https://www.googleapis.com/oauth2/v3/tokeninfo"
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

	// Bade request indicates invalid token.
	if resp.StatusCode == http.StatusBadRequest {
		return veles.ValidationInvalid, nil
	}

	if resp.StatusCode != http.StatusOK {
		return veles.ValidationFailed, fmt.Errorf("unexpected response status: %d", resp.StatusCode)
	}

	// Token is recognized. Check scopes and expiration.

	if tokenInfo.Scope == "" {
		// Token does not have access to any scopes.
		return veles.ValidationInvalid, nil
	}

	expiresIn, err := strconv.ParseInt(tokenInfo.ExpiresIn, 10, 64)
	if err == nil {
		if expiresIn > 0 {
			return veles.ValidationValid, nil
		}
		return veles.ValidationInvalid, nil
	}

	expiresAt, err := strconv.ParseInt(tokenInfo.Expiry, 10, 64)
	if err == nil && expiresAt > 0 {
		expire := time.Unix(expiresAt, 0)
		if time.Now().Before(expire) {
			return veles.ValidationValid, nil
		}
		return veles.ValidationInvalid, nil
	}

	// If we can't determine expiration, consider validation failed
	return veles.ValidationFailed, errors.New("failed to determine token expiration")
}
