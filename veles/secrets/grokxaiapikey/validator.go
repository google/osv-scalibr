// Copyright 2026 Google LLC
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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	// Used to validate standard API keys directly by checking blocked/disabled flags.
	apiEndpoint = "https://api.x.ai/v1/api-key"
	// Uses a dummy teamId since every management API request requires {teamId}.
	// This forces predictable error patterns that allow indirect validation of management keys.
	managementEndpoint = "https://management-api.x.ai/auth/teams/ffffffff-ffff-ffff-ffff-ffffffffffff/api-keys"
	// validationTimeout is timeout for API validation requests.
	validationTimeout = 10 * time.Second
)

//
// --- Grok XAI API Key Validator ---
//

// apiKeyResponse represents the JSON returned by the x.ai API key endpoint.
type apiKeyResponse struct {
	APIKeyBlocked  bool `json:"api_key_blocked"`
	APIKeyDisabled bool `json:"api_key_disabled"`
}

// apiKeyStatusFromBody verifies responses from /v1/api-key.
// If either api_key_blocked or api_key_disabled is true, the key is invalid.
func apiKeyStatusFromBody(body io.Reader) (veles.ValidationStatus, error) {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to read response body: %w", err)
	}
	var resp apiKeyResponse
	if err := json.Unmarshal(bodyBytes, &resp); err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	if resp.APIKeyBlocked || resp.APIKeyDisabled {
		return veles.ValidationInvalid, nil
	}
	return veles.ValidationValid, nil
}

// NewAPIValidator creates a new Validator for GrokXAIAPIKey.
func NewAPIValidator() *simplevalidate.Validator[GrokXAIAPIKey] {
	return &simplevalidate.Validator[GrokXAIAPIKey]{
		Endpoint:   apiEndpoint,
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(k GrokXAIAPIKey) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + k.Key,
			}
		},
		StatusFromResponseBody: apiKeyStatusFromBody,
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}
}

//
// --- Grok XAI Management Key Validator ---
//

// managementErrorResponse represents the JSON returned when a management key is checked.
type managementErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func managementKeyStatusFromBody(body io.Reader) (veles.ValidationStatus, error) {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to read response body: %w", err)
	}

	var resp managementErrorResponse
	if err := json.Unmarshal(bodyBytes, &resp); err != nil {
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
}

// NewManagementAPIValidator creates a new Validator for GrokXAIManagementKey.
func NewManagementAPIValidator() *simplevalidate.Validator[GrokXAIManagementKey] {
	return &simplevalidate.Validator[GrokXAIManagementKey]{
		Endpoint:   managementEndpoint,
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(k GrokXAIManagementKey) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + k.Key,
			}
		},
		ValidResponseCodes:     []int{http.StatusOK},
		InvalidResponseCodes:   []int{http.StatusUnauthorized},
		StatusFromResponseBody: managementKeyStatusFromBody,
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}
}
