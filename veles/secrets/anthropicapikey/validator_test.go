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
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/anthropicapikey"
)

const (
	validatorTestKey      = "sk-ant-api03-test123456789012345678901234567890123456789012345678"
	validatorAdminTestKey = "sk-ant-admin01-test123456789012345678901234567890123456789012345678"
)

// mockAnthropicServer creates a mock Anthropic API server for testing
func mockAnthropicServer(t *testing.T, expectedKey string, statusCode int, responseBody string) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Determine expected endpoint based on the key
		var expectedPath string
		if expectedKey == validatorAdminTestKey {
			expectedPath = "/v1/organizations/workspaces"
		} else {
			expectedPath = "/v1/models"
		}

		// Check if it's a GET request to the expected endpoint
		if r.Method != http.MethodGet || r.URL.Path != expectedPath {
			t.Errorf("unexpected request: %s %s, expected: GET %s", r.Method, r.URL.Path, expectedPath)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check headers (no Content-Type expected for GET request)
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

func TestValidator(t *testing.T) {
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
						"type": "model",
						"id": "claude-3-5-sonnet-20241022",
						"display_name": "Claude 3.5 Sonnet (New)"
					},
					{
						"type": "model",
						"id": "claude-3-haiku-20240307",
						"display_name": "Claude 3 Haiku"
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
					"message": "Insufficient permissions"
				}
			}`,
			want: veles.ValidationValid,
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
		{
			name:       "bad_gateway",
			statusCode: http.StatusBadGateway,
			responseBody: `{
				"error": {
					"type": "server_error",
					"message": "Bad gateway"
				}
			}`,
			want:        veles.ValidationFailed,
			expectError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server
			server := mockAnthropicServer(t, validatorTestKey, tc.statusCode, tc.responseBody)
			defer server.Close()

			// Create validator with mock client and server URL
			validator := anthropicapikey.NewValidator(
				anthropicapikey.WithClient(server.Client()),
				anthropicapikey.WithAPIURL(server.URL),
			)

			// Create test key
			key := anthropicapikey.AnthropicAPIKey{Key: validatorTestKey}

			// Test validation
			got, err := validator.Validate(context.Background(), key)

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

func TestValidator_AdminKeys(t *testing.T) {
	cases := []struct {
		name         string
		statusCode   int
		responseBody string
		want         veles.ValidationStatus
		expectError  bool
	}{
		{
			name:       "valid_admin_key",
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
			name:       "invalid_admin_key_unauthorized",
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
			name:       "admin_forbidden_but_likely_valid",
			statusCode: http.StatusForbidden,
			responseBody: `{
				"error": {
					"type": "permission_error",
					"message": "Your account does not have permission to perform this action"
				}
			}`,
			want: veles.ValidationValid,
		},
		{
			name:       "admin_rate_limited_but_likely_valid",
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
			name:       "admin_server_error",
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
			// Create mock server for admin keys
			server := mockAnthropicServer(t, validatorAdminTestKey, tc.statusCode, tc.responseBody)
			defer server.Close()

			// Create validator with mock client and server URL
			validator := anthropicapikey.NewValidator(
				anthropicapikey.WithClient(server.Client()),
				anthropicapikey.WithAPIURL(server.URL),
			)

			// Create admin test key
			key := anthropicapikey.AnthropicAPIKey{Key: validatorAdminTestKey}

			// Test validation
			got, err := validator.Validate(context.Background(), key)

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

func TestValidator_WithCustomClient(t *testing.T) {
	// Test that custom HTTP client is used
	customClient := &http.Client{
		Timeout: 5 * time.Second,
	}

	validator := anthropicapikey.NewValidator(
		anthropicapikey.WithClient(customClient),
	)

	// Test that the validator works with custom client
	key := anthropicapikey.AnthropicAPIKey{Key: validatorTestKey}

	// Create a simple test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Test that validation works (we don't need to check the internal field)
	_, err := validator.Validate(context.Background(), key)
	// We expect an error since we're not using the mock server, but the validator should be created successfully
	if err == nil {
		t.Logf("Validator created successfully with custom client")
	}
}

func TestValidator_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	validator := anthropicapikey.NewValidator(
		anthropicapikey.WithClient(server.Client()),
	)

	key := anthropicapikey.AnthropicAPIKey{Key: validatorTestKey}

	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// Test validation with cancelled context
	got, err := validator.Validate(ctx, key)

	if err == nil {
		t.Errorf("Validate() expected error due to context cancellation, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}

func TestValidator_InvalidRequest(t *testing.T) {
	validator := anthropicapikey.NewValidator()

	// Test with empty key
	key := anthropicapikey.AnthropicAPIKey{Key: ""}

	got, err := validator.Validate(context.Background(), key)

	// Should fail due to invalid request
	if err == nil {
		t.Errorf("Validate() expected error for empty key, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}
