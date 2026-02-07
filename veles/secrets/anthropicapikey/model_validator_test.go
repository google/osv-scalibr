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

package anthropicapikey_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/anthropicapikey"
)

const (
	modelValidatorTestKey = "sk-ant-api03-test123456789012345678901234567890123456789012345678"
)

// mockAnthropicModelServer creates a mock Anthropic API server for testing model keys
func mockAnthropicModelServer(t *testing.T, expectedKey string, statusCode int, responseBody string) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		modelsEndpoint := anthropicapikey.AnthropicModelsEndpoint
		// Check if it's a GET request to the models endpoint
		if r.Method != http.MethodGet || r.URL.Path != modelsEndpoint {
			t.Errorf("unexpected request: %s %s, expected: GET %s", r.Method, r.URL.Path, modelsEndpoint)
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

func TestModelValidator(t *testing.T) {
	cases := []struct {
		name         string
		statusCode   int
		responseBody string
		want         veles.ValidationStatus
		expectError  bool
	}{
		{
			name:       "valid_key",
			statusCode: http.StatusOK,
			responseBody: `{
				"data": [
					{
						"id": "claude-3-opus-20240229",
						"object": "model",
						"created": 1709251200,
						"owned_by": "anthropic"
					}
				]
			}`,
			want: veles.ValidationValid,
		},
		{
			name:       "invalid_key_unauthorized",
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
			name:       "forbidden_but_likely_valid",
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
			name:       "rate_limited_but_likely_valid",
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
			name:       "server_error",
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
			server := mockAnthropicModelServer(t, modelValidatorTestKey, tc.statusCode, tc.responseBody)
			defer server.Close()

			// Create validator with mock client and server URL
			validator := anthropicapikey.NewModelValidator()
			validator.HTTPC = server.Client()
			validator.Endpoint = server.URL + anthropicapikey.AnthropicModelsEndpoint

			// Create test key
			key := anthropicapikey.ModelAPIKey{Key: modelValidatorTestKey}

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
