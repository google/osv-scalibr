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

package gcpoauth2access

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

const (
	// endpoint is the URL of Google's OAuth2 tokeninfo endpoint.
	// https://developers.google.com/identity/protocols/oauth2
	endpoint = "https://www.googleapis.com/oauth2/v3/tokeninfo"
)

var _ veles.Validator[Token] = NewValidator()

// ValidatorOption configures a validator when creating it via NewValidator.
type ValidatorOption func(*validator)

// validator implements veles.Validator for GCP OAuth2 access tokens.
type validator struct {
	client *http.Client
}

// WithClient configures the http.Client that the validator uses.
//
// By default it uses http.DefaultClient.
func WithClient(c *http.Client) ValidatorOption {
	return func(v *validator) {
		v.client = c
	}
}

// NewValidator creates a new Validator for GCP OAuth2 access tokens.
func NewValidator(opts ...ValidatorOption) veles.Validator[Token] {
	v := &validator{
		client: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// response represents the response from Google's OAuth2 token endpoint.
// https://developers.google.com/identity/protocols/oauth2
type response struct {
	// Expiry is the expiration time of the token in Unix time.
	Expiry string `json:"exp"`
	// ExpiresIn is the number of seconds until the token expires.
	ExpiresIn string `json:"expires_in"`
	// Scope is a space-delimited list that identify the resources that your application could access
	// https://developers.google.com/identity/protocols/oauth2/scopes
	Scope string `json:"scope"`
}

// Validate checks if a GCP OAuth2 access token is valid by calling Google's tokeninfo endpoint.
func (v *validator) Validate(ctx context.Context, token Token) (veles.ValidationStatus, error) {
	if token.Token == "" {
		return veles.ValidationFailed, errors.New("empty token")
	}

	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to parse endpoint: %w", err)
	}

	params := url.Values{}
	params.Set("access_token", token.Token)
	endpointURL.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL.String(), nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to validate token: %w", err)
	}
	defer resp.Body.Close()

	// Bad request indicates invalid token.
	if resp.StatusCode == http.StatusBadRequest {
		return veles.ValidationInvalid, nil
	}

	if resp.StatusCode != http.StatusOK {
		return veles.ValidationFailed, fmt.Errorf("unexpected response status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to read response: %w", err)
	}

	var tokenInfo response
	if err := json.Unmarshal(body, &tokenInfo); err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to parse response: %w", err)
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
