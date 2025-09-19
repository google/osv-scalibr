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

package gcpoauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/osv-scalibr/veles"
)

// Validator validates GCP OAuth2 client credentials.
type Validator struct {
	client *http.Client
}

// NewValidator creates a new validator for GCP OAuth2 client credentials.
func NewValidator() *Validator {
	return &Validator{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Validate checks if the GCP OAuth2 client credentials are valid.
// It uses Google's OAuth2 token info endpoint to validate the credentials.
func (v *Validator) Validate(ctx context.Context, secret ClientCredentials) (veles.ValidationStatus, error) {
	// We need both client ID and secret for full validation
	if secret.ClientID == "" || secret.ClientSecret == "" {
		// For partial credentials, we can only do basic format validation
		if secret.ClientID != "" {
			if clientIDRe.MatchString(secret.ClientID) {
				return veles.ValidationValid, nil
			}
			return veles.ValidationInvalid, nil
		}
		if secret.ClientSecret != "" {
			if clientSecretRe.MatchString(secret.ClientSecret) {
				return veles.ValidationValid, nil
			}
			return veles.ValidationInvalid, nil
		}
		if secret.ID != "" {
			if clientIDRe.MatchString(secret.ID) {
				return veles.ValidationValid, nil
			}
			return veles.ValidationInvalid, nil
		}
		return veles.ValidationInvalid, nil
	}

	// Validate by attempting to exchange credentials for a token using client_credentials flow
	// This is a safe way to validate without affecting user sessions
	tokenURL := "https://oauth2.googleapis.com/token"

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", secret.ClientID)
	data.Set("client_secret", secret.ClientSecret)
	// Use a minimal scope that should be available for most OAuth2 clients
	data.Set("scope", "https://www.googleapis.com/auth/userinfo.email")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "OSV-SCALIBR/1.0")

	resp, err := v.client.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Successfully got a token, credentials are valid
		return veles.ValidationValid, nil
	case http.StatusBadRequest, http.StatusUnauthorized:
		// Invalid credentials
		var errorResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err == nil {
			if errorResp.Error == "invalid_client" || errorResp.Error == "invalid_grant" {
				return veles.ValidationInvalid, nil
			}
		}
		return veles.ValidationInvalid, nil
	default:
		// Unexpected response, treat as validation failure
		return veles.ValidationFailed, fmt.Errorf("unexpected response status: %d", resp.StatusCode)
	}
}
