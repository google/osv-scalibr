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

// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package grokxaiapikey

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/osv-scalibr/veles"
)

const (
	// Used to validate standard API keys directly by checking blocked/disabled flags.
	apiEndpoint = "https://api.x.ai/v1/api-key"
	// Uses a dummy teamId since every management API request requires {teamId}.
	// This forces predictable error patterns that allow indirect validation of management keys.
	managementEndpoint = "https://management-api.x.ai/auth/teams/ffffffff-ffff-ffff-ffff-ffffffffffff/api-keys"
)

//
// --- Grok XAI API Key Validator ---
//

var _ veles.Validator[GrokXAIAPIKey] = &ValidatorAPI{}

// ValidatorAPI validates Grok XAI API Keys using the x.ai /v1/api-key endpoint.
type ValidatorAPI struct {
	httpC *http.Client
}

// ValidatorOptionAPI configures a ValidatorAPI when creating it via NewAPIValidator.
type ValidatorOptionAPI func(*ValidatorAPI)

// WithClientAPI configures the http.Client used by ValidatorAPI.
//
// By default it uses http.DefaultClient.
func WithClientAPI(c *http.Client) ValidatorOptionAPI {
	return func(v *ValidatorAPI) {
		v.httpC = c
	}
}

// NewAPIValidator creates a new ValidatorAPI with the given options.
func NewAPIValidator(opts ...ValidatorOptionAPI) *ValidatorAPI {
	v := &ValidatorAPI{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// apiKeyResponse represents the JSON returned by the x.ai API key endpoint.
type apiKeyResponse struct {
	APIKeyBlocked  bool `json:"api_key_blocked"`
	APIKeyDisabled bool `json:"api_key_disabled"`
}

// Validate checks whether the given GrokXAIAPIKey is valid.
//
// It calls /v1/api-key with the key as a Bearer token. If either
// api_key_blocked or api_key_disabled is true, the key is invalid.
func (v *ValidatorAPI) Validate(ctx context.Context, key GrokXAIAPIKey) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiEndpoint, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+key.Key)

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to GET %q: %w", apiEndpoint, err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return veles.ValidationFailed, fmt.Errorf("unexpected status %q from %q", res.Status, apiEndpoint)
	}

	var resp apiKeyResponse
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to parse response from %q: %w", apiEndpoint, err)
	}

	if resp.APIKeyBlocked || resp.APIKeyDisabled {
		return veles.ValidationInvalid, nil
	}
	return veles.ValidationValid, nil
}

//
// --- Grok XAI Management Key Validator ---
//

var _ veles.Validator[GrokXAIManagementKey] = &ValidatorManagement{}

// ValidatorManagement validates Grok XAI Management Keys using the management-api.x.ai endpoint.
type ValidatorManagement struct {
	httpC *http.Client
}

// ValidatorOptionManagement configures a ValidatorManagement when creating it via NewManagementAPIValidator.
type ValidatorOptionManagement func(*ValidatorManagement)

// WithClientManagement configures the http.Client used by ValidatorManagement.
//
// By default it uses http.DefaultClient.
func WithClientManagement(c *http.Client) ValidatorOptionManagement {
	return func(v *ValidatorManagement) {
		v.httpC = c
	}
}

// NewManagementAPIValidator creates a new ValidatorManagement with the given options.
func NewManagementAPIValidator(opts ...ValidatorOptionManagement) *ValidatorManagement {
	v := &ValidatorManagement{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// managementErrorResponse represents the JSON returned when a management key is checked.
type managementErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Validate checks whether the given GrokXAIManagementKey is valid.
//
// It calls the management endpoint with the key as a Bearer token.
func (v *ValidatorManagement) Validate(ctx context.Context, key GrokXAIManagementKey) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, managementEndpoint, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+key.Key)

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to GET %q: %w", managementEndpoint, err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		// A 200 OK from the management API does indicate a valid key.
		return veles.ValidationValid, nil

	case http.StatusUnauthorized:
		// Invalid bearer token.
		// The API rejects the token entirely (code 16 "Invalid bearer token"),
		// which means the key is malformed, expired, or simply does not exist.
		return veles.ValidationInvalid, nil

	case http.StatusForbidden:
		var resp managementErrorResponse
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			return veles.ValidationFailed, fmt.Errorf("unable to parse response from %q: %w", managementEndpoint, err)
		}
		if resp.Code == 7 {
			// Team mismatch error → means the key itself is valid.
			// Every management API call requires a {teamId}, but we don't know the real one.
			// By using a fake teamId, a valid key passes authentication but fails authorization,
			// producing code 7 ("team mismatch"). This reliably distinguishes valid keys from invalid ones.
			return veles.ValidationValid, nil
		}
		// Other 403 codes → the key was authenticated but failed authorization for reasons other than team mismatch.
		// This indicates the key is not valid for use.
		return veles.ValidationInvalid, nil

	default:
		return veles.ValidationFailed, fmt.Errorf("unexpected status %q from %q", res.Status, managementEndpoint)
	}
}
