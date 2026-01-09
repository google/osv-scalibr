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

package anthropicapikey_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/anthropicapikey"
)

const (
	workspaceValidatorTestKey = "sk-ant-admin01-test123456789012345678901234567890123456789012345678"
)

// mockAnthropicWorkspaceServer creates a mock Anthropic API server for testing workspace keys
func mockAnthropicWorkspaceServer(t *testing.T, expectedKey string, statusCode int, responseBody string) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		workspacesEndpoint := anthropicapikey.AnthropicWorkspacesEndpoint
		// Check if it's a GET request to the workspaces endpoint
		if r.Method != http.MethodGet || r.URL.Path != workspacesEndpoint {
			t.Errorf("unexpected request: %s %s, expected: GET %s", r.Method, r.URL.Path, workspacesEndpoint)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check headers
		if r.Header.Get("X-Api-Key") != expectedKey {
			t.Errorf("expected X-Api-Key: %s, got: %s", expectedKey, r.Header.Get("X-Api-Key"))
		}
		if r.Header.Get("Anthropic-Version") != "2023-06-01" {
			t.Errorf("expected Anthropic-Version: 2023-06-01, got: %s", r.Header.Get("Anthropic-Version"))
		}

		// Set response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if responseBody != "" {
			if _, err := w.Write([]byte(responseBody)); err != nil {
				t.Errorf("unable to write response: %v", err)
			}
		}
	}))

	return server
}

func TestWorkspaceValidator(t *testing.T) {
	cases := []struct {
		name         string
		statusCode   int
		responseBody string
		want         veles.ValidationStatus
		expectError  bool
	}{
		{
			name:       "valid_workspace_key",
			statusCode: http.StatusOK,
			responseBody: `{
				"data": [
					{
						"type": "organization",
						"id": "org_123456789012345678901234",
						"name": "Example Organization"
					}
				]
			}`,
			want: veles.ValidationValid,
		},
		{
			name:       "invalid_workspace_key_unauthorized",
			statusCode: http.StatusUnauthorized,
			responseBody: `{
				"error": {
					"type": "authentication_error",
					"message": "Invalid API key"
				}
			}`,
			want: veles.ValidationInvalid,
		},
		{
			name:       "workspace_forbidden_but_likely_valid",
			statusCode: http.StatusForbidden,
			responseBody: `{
				"error": {
					"type": "permission_error",
					"message": "Your account does not have permission to perform this action"
				}
			}`,
			want:        veles.ValidationFailed,
			expectError: true,
		},
		{
			name:       "workspace_rate_limited_but_likely_valid",
			statusCode: http.StatusTooManyRequests,
			responseBody: `{
				"error": {
					"type": "rate_limit_error",
					"message": "Rate limit exceeded"
				}
			}`,
			want: veles.ValidationValid,
		},
		{
			name:       "workspace_server_error",
			statusCode: http.StatusInternalServerError,
			responseBody: `{
				"error": {
					"type": "server_error",
					"message": "Internal server error"
				}
			}`,
			want:        veles.ValidationFailed,
			expectError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server
			server := mockAnthropicWorkspaceServer(t, workspaceValidatorTestKey, tc.statusCode, tc.responseBody)
			defer server.Close()

			// Create validator with mock client and server URL
			validator := anthropicapikey.NewWorkspaceValidator()
			validator.HTTPC = server.Client()
			validator.Endpoint = server.URL + anthropicapikey.AnthropicWorkspacesEndpoint

			// Create test key
			key := anthropicapikey.WorkspaceAPIKey{Key: workspaceValidatorTestKey}

			// Test validation
			got, err := validator.Validate(t.Context(), key)

			// Check error expectation
			if tc.expectError {
				if err == nil {
					t.Errorf("Validate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}

			// Check validation status
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}
