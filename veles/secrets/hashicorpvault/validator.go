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

package hashicorpvault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/osv-scalibr/veles"
)

// TokenValidator validates HashiCorp Vault tokens via the Vault API.
type TokenValidator struct {
	httpC    *http.Client
	vaultURL string
}

// AppRoleValidator validates HashiCorp Vault AppRole credentials via the Vault API.
type AppRoleValidator struct {
	httpC    *http.Client
	vaultURL string
}

// ValidatorOption configures a Validator when creating it.
type ValidatorOption func(any)

// WithClient configures the http.Client that the Validator uses.
// By default it uses http.DefaultClient.
func WithClient(c *http.Client) ValidatorOption {
	return func(v any) {
		switch validator := v.(type) {
		case *TokenValidator:
			validator.httpC = c
		case *AppRoleValidator:
			validator.httpC = c
		}
	}
}

// WithVaultURL configures the Vault URL that the Validator uses.
// This should be the base URL of the Vault instance (e.g., "https://vault.company.com").
func WithVaultURL(vaultURL string) ValidatorOption {
	return func(v any) {
		switch validator := v.(type) {
		case *TokenValidator:
			validator.vaultURL = vaultURL
		case *AppRoleValidator:
			validator.vaultURL = vaultURL
		}
	}
}

// NewTokenValidator creates a new TokenValidator with the given ValidatorOptions.
func NewTokenValidator(opts ...ValidatorOption) *TokenValidator {
	v := &TokenValidator{
		httpC:    http.DefaultClient,
		vaultURL: "https://vault.company.com", // Default placeholder URL
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// NewAppRoleValidator creates a new AppRoleValidator with the given ValidatorOptions.
func NewAppRoleValidator(opts ...ValidatorOption) *AppRoleValidator {
	v := &AppRoleValidator{
		httpC:    http.DefaultClient,
		vaultURL: "https://vault.company.com", // Default placeholder URL
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given Token is valid by using the Vault token lookup-self API.
// It performs a GET request to /v1/auth/token/lookup-self with the token in the X-Vault-Token header.
// Returns ValidationValid for 200 OK, ValidationInvalid for 401/403, ValidationFailed for other errors.
func (v *TokenValidator) Validate(ctx context.Context, token Token) (veles.ValidationStatus, error) {
	apiURL, err := url.JoinPath(v.vaultURL, "/v1/auth/token/lookup-self")
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("invalid vault URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token.Token)

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		return veles.ValidationValid, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return veles.ValidationInvalid, nil
	default:
		return veles.ValidationFailed, fmt.Errorf("unexpected HTTP status: %d", res.StatusCode)
	}
}

// AppRoleLoginRequest represents the request body for AppRole login.
type AppRoleLoginRequest struct {
	RoleID   string `json:"role_id"`
	SecretID string `json:"secret_id"`
}

// Validate checks whether the given AppRoleCredentials are valid by using the Vault AppRole login API.
// It performs a POST request to /v1/auth/approle/login with role-id and secret-id.
// Note: Since the detector cannot distinguish between role-id and secret-id, this validation
// is limited. In practice, both values would need to be provided together.
// Returns ValidationValid for 200 OK, ValidationInvalid for 401/400, ValidationFailed for other errors.
func (v *AppRoleValidator) Validate(ctx context.Context, credentials AppRoleCredentials) (veles.ValidationStatus, error) {
	// If we don't have both role_id and secret_id, we cannot validate AppRole credentials
	if credentials.RoleID == "" || credentials.SecretID == "" {
		return veles.ValidationFailed, errors.New("both role_id and secret_id are required for AppRole validation")
	}

	apiURL, err := url.JoinPath(v.vaultURL, "/v1/auth/approle/login")
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("invalid vault URL: %w", err)
	}

	requestBody := AppRoleLoginRequest{
		RoleID:   credentials.RoleID,
		SecretID: credentials.SecretID,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("HTTP POST failed: %w", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		return veles.ValidationValid, nil
	case http.StatusUnauthorized, http.StatusBadRequest:
		return veles.ValidationInvalid, nil
	default:
		return veles.ValidationFailed, fmt.Errorf("unexpected HTTP status: %d", res.StatusCode)
	}
}
