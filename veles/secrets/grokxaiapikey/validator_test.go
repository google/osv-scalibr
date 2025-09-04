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

package grokxaiapikey_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/osv-scalibr/veles"
	grokxaiapikey "github.com/google/osv-scalibr/veles/secrets/grokxaiapikey"
)

const validatorTestKey = "grokx-test12345678901234567890123456789012345678901234567890"

// mockTransport redirects requests to the test server for the configured hosts.
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL for both API hosts.
	if req.URL.Host == "api.x.ai" || req.URL.Host == "management-api.x.ai" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockAPIServer creates a mock x.ai /v1/api-key endpoint for testing API validator.
func mockAPIServer(t *testing.T, expectedKey string, statusCode int, body any) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Expect a GET to /v1/api-key
		if r.Method != http.MethodGet || r.URL.Path != "/v1/api-key" {
			t.Errorf("unexpected request: %s %s, expected: GET /v1/api-key", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Authorization header contains the key (ends with key)
		authHeader := r.Header.Get("Authorization")
		if !strings.HasSuffix(authHeader, expectedKey) {
			t.Errorf("expected Authorization header to end with key %s, got: %s", expectedKey, authHeader)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

// mockManagementServer creates a mock management endpoint for testing management validator.
func mockManagementServer(t *testing.T, expectedKey string, statusCode int, body any) *httptest.Server {
	t.Helper()

	// The managementEndpoint path in the validator is:
	// /auth/teams/ffffffff-ffff-ffff-ffff-ffffffffffff/api-keys
	expectedPath := "/auth/teams/ffffffff-ffff-ffff-ffff-ffffffffffff/api-keys"

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Expect a GET to the management path
		if r.Method != http.MethodGet || r.URL.Path != expectedPath {
			t.Errorf("unexpected request: %s %s, expected: GET %s", r.Method, r.URL.Path, expectedPath)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Authorization header contains the key (ends with key)
		authHeader := r.Header.Get("Authorization")
		if !strings.HasSuffix(authHeader, expectedKey) {
			t.Errorf("expected Authorization header to end with key %s, got: %s", expectedKey, authHeader)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestValidatorAPI(t *testing.T) {
	cases := []struct {
		name        string
		statusCode  int
		body        any
		want        veles.ValidationStatus
		expectError bool
	}{
		{
			name:       "valid_key",
			statusCode: http.StatusOK,
			body: map[string]bool{
				"api_key_blocked":  false,
				"api_key_disabled": false,
			},
			want: veles.ValidationValid,
		},
		{
			name:       "blocked_key",
			statusCode: http.StatusOK,
			body: map[string]bool{
				"api_key_blocked":  true,
				"api_key_disabled": false,
			},
			want: veles.ValidationInvalid,
		},
		{
			name:       "disabled_key",
			statusCode: http.StatusOK,
			body: map[string]bool{
				"api_key_blocked":  false,
				"api_key_disabled": true,
			},
			want: veles.ValidationInvalid,
		},
		{
			name:        "unauthorized_status",
			statusCode:  http.StatusUnauthorized,
			body:        nil,
			want:        veles.ValidationFailed,
			expectError: true,
		},
		{
			name:        "server_error",
			statusCode:  http.StatusInternalServerError,
			body:        nil,
			want:        veles.ValidationFailed,
			expectError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server
			server := mockAPIServer(t, validatorTestKey, tc.statusCode, tc.body)
			defer server.Close()

			// Create client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create validator with mock client
			validator := grokxaiapikey.NewAPIValidator(
				grokxaiapikey.WithClientAPI(client),
			)

			// Create test key
			key := grokxaiapikey.GrokXAIAPIKey{Key: validatorTestKey}

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

func TestValidatorAPI_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"api_key_blocked": false, "api_key_disabled": false}`))
	}))
	defer server.Close()

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := grokxaiapikey.NewAPIValidator(
		grokxaiapikey.WithClientAPI(client),
	)

	key := grokxaiapikey.GrokXAIAPIKey{Key: validatorTestKey}

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

func TestValidatorAPI_InvalidRequest(t *testing.T) {
	// For API validator, an "invalid" key is communicated via the JSON flags.
	// Create mock server that returns a 200 with api_key_blocked true for empty/invalid keys.
	server := mockAPIServer(t, "", http.StatusOK, map[string]bool{
		"api_key_blocked":  true,
		"api_key_disabled": false,
	})
	defer server.Close()

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := grokxaiapikey.NewAPIValidator(
		grokxaiapikey.WithClientAPI(client),
	)

	testCases := []struct {
		name     string
		key      string
		expected veles.ValidationStatus
	}{
		{
			name:     "empty_key",
			key:      "",
			expected: veles.ValidationInvalid,
		},
		{
			name:     "invalid_key_format",
			key:      "invalid-key-format",
			expected: veles.ValidationInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k := grokxaiapikey.GrokXAIAPIKey{Key: tc.key}

			got, err := validator.Validate(context.Background(), k)

			if err != nil {
				t.Errorf("Validate() unexpected error for %s: %v", tc.name, err)
			}
			if got != tc.expected {
				t.Errorf("Validate() = %v, want %v for %s", got, tc.expected, tc.name)
			}
		})
	}
}

func TestValidatorManagement(t *testing.T) {
	cases := []struct {
		name        string
		statusCode  int
		body        any
		want        veles.ValidationStatus
		expectError bool
	}{
		{
			name:       "valid_key_team_mismatch",
			statusCode: http.StatusForbidden,
			body: map[string]any{
				"code":    7,
				"message": "team mismatch",
			},
			want: veles.ValidationValid,
		},
		{
			name:       "invalid_key_unauthorized",
			statusCode: http.StatusUnauthorized,
			body:       nil,
			want:       veles.ValidationInvalid,
		},
		{
			name:       "forbidden_other_code",
			statusCode: http.StatusForbidden,
			body: map[string]any{
				"code":    42,
				"message": "other reason",
			},
			want: veles.ValidationInvalid,
		},
		{
			name:        "server_error",
			statusCode:  http.StatusInternalServerError,
			body:        nil,
			want:        veles.ValidationFailed,
			expectError: true,
		},
		{
			name:        "forbidden_bad_json",
			statusCode:  http.StatusForbidden,
			body:        "not-a-json", // this will be encoded as a string -> invalid JSON structure for decoding
			expectError: true,
			want:        veles.ValidationFailed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock management server
			server := mockManagementServer(t, validatorTestKey, tc.statusCode, tc.body)
			defer server.Close()

			// Create client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create validator with mock client
			validator := grokxaiapikey.NewManagementAPIValidator(
				grokxaiapikey.WithClientManagement(client),
			)

			// Create test key
			key := grokxaiapikey.GrokXAIManagementKey{Key: validatorTestKey}

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

func TestValidatorManagement_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":7,"message":"team mismatch"}`))
	}))
	defer server.Close()

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := grokxaiapikey.NewManagementAPIValidator(
		grokxaiapikey.WithClientManagement(client),
	)

	key := grokxaiapikey.GrokXAIManagementKey{Key: validatorTestKey}

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

func TestValidatorManagement_InvalidRequest(t *testing.T) {
	// For management validator, a 401 indicates invalid token (no error returned).
	server := mockManagementServer(t, "", http.StatusUnauthorized, nil)
	defer server.Close()

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := grokxaiapikey.NewManagementAPIValidator(
		grokxaiapikey.WithClientManagement(client),
	)

	testCases := []struct {
		name     string
		key      string
		expected veles.ValidationStatus
	}{
		{
			name:     "empty_key",
			key:      "",
			expected: veles.ValidationInvalid,
		},
		{
			name:     "invalid_key_format",
			key:      "invalid-management-key",
			expected: veles.ValidationInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k := grokxaiapikey.GrokXAIManagementKey{Key: tc.key}

			got, err := validator.Validate(context.Background(), k)

			if err != nil {
				t.Errorf("Validate() unexpected error for %s: %v", tc.name, err)
			}
			if got != tc.expected {
				t.Errorf("Validate() = %v, want %v for %s", got, tc.expected, tc.name)
			}
		})
	}
}
