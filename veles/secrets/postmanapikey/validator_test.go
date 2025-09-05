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

package postmanapikey_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/osv-scalibr/veles"
	postmanapikey "github.com/google/osv-scalibr/veles/secrets/postmanapikey"
)

const (
	validatorTestAPIKey        = "PMAK-68b96bd4ae8d2b0001db8a86-192b1cb49020c70a4d0c814ab71de822d7"
	validatorTestCollectionKey = "PMAT-01K4A58P2HS2Q43TXHSXFRDBZX"
)

// mockTransport redirects requests to the test server for the configured hosts.
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL for Postman API hosts.
	if req.URL.Host == "api.getpostman.com" || req.URL.Host == "api.postman.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockAPIServer creates a mock Postman /me endpoint for testing API validator.
func mockAPIServer(t *testing.T, expectedKey string, statusCode int, body any) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Expect a GET to /me
		if r.Method != http.MethodGet || r.URL.Path != "/me" {
			t.Errorf("unexpected request: %s %s, expected: GET /me", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check X-Api-Key header contains the expected key
		apiKeyHeader := r.Header.Get("X-Api-Key")
		if expectedKey != "" && apiKeyHeader != expectedKey {
			t.Errorf("expected X-Api-Key header to be %s, got: %s", expectedKey, apiKeyHeader)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

// mockCollectionServer creates a mock Postman collection endpoint for testing collection validator.
func mockCollectionServer(t *testing.T, expectedKey string, statusCode int, body any) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Expect a GET to /collections/aaaaaaaa-aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa
		expectedPath := "/collections/aaaaaaaa-aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa"
		if r.Method != http.MethodGet || r.URL.Path != expectedPath {
			t.Errorf("unexpected request: %s %s, expected: GET %s", r.Method, r.URL.Path, expectedPath)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check access_key query parameter
		if expectedKey != "" {
			accessKey := r.URL.Query().Get("access_key")
			if accessKey != expectedKey {
				t.Errorf("expected access_key query parameter to be %s, got: %s", expectedKey, accessKey)
			}
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
			body: map[string]any{
				"user": map[string]any{
					"id":   12345,
					"name": "Test User",
				},
			},
			want: veles.ValidationValid,
		},
		{
			name:       "invalid_key_unauthorized",
			statusCode: http.StatusUnauthorized,
			body: map[string]any{
				"error": map[string]any{
					"name":    "AuthenticationError",
					"message": "Invalid API Key. Every request requires a valid API Key to be sent.",
				},
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
			name:        "forbidden_error",
			statusCode:  http.StatusForbidden,
			body:        nil,
			want:        veles.ValidationFailed,
			expectError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server
			server := mockAPIServer(t, validatorTestAPIKey, tc.statusCode, tc.body)
			defer server.Close()

			// Create client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create validator with mock client
			validator := postmanapikey.NewAPIValidator(
				postmanapikey.WithClientAPI(client),
			)

			// Create test key
			key := postmanapikey.PostmanAPIKey{Key: validatorTestAPIKey}

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
		_, _ = w.Write([]byte(`{"user": {"id": 12345, "name": "Test User"}}`))
	}))
	defer server.Close()

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := postmanapikey.NewAPIValidator(
		postmanapikey.WithClientAPI(client),
	)

	key := postmanapikey.PostmanAPIKey{Key: validatorTestAPIKey}

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
	// For API validator, an "invalid" key is communicated via 401 status.
	server := mockAPIServer(t, "", http.StatusUnauthorized, map[string]any{
		"error": map[string]any{
			"name":    "AuthenticationError",
			"message": "Invalid API Key. Every request requires a valid API Key to be sent.",
		},
	})
	defer server.Close()

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := postmanapikey.NewAPIValidator(
		postmanapikey.WithClientAPI(client),
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
			key:      "invalid-api-key-format",
			expected: veles.ValidationInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k := postmanapikey.PostmanAPIKey{Key: tc.key}

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

func TestValidatorCollection(t *testing.T) {
	cases := []struct {
		name        string
		statusCode  int
		body        any
		want        veles.ValidationStatus
		expectError bool
	}{
		{
			name:       "valid_key_with_access",
			statusCode: http.StatusOK,
			want:       veles.ValidationValid,
		},
		{
			name:       "valid_key_forbidden_exact_match",
			statusCode: http.StatusForbidden,
			body: map[string]any{
				"error": map[string]any{
					"name":    "forbiddenError",
					"message": "You are not authorized to perform this action.",
				},
			},
			want: veles.ValidationValid,
		},
		{
			name:       "invalid_key_unauthorized",
			statusCode: http.StatusUnauthorized,
			body: map[string]any{
				"error": map[string]any{
					"name":    "AuthenticationError",
					"message": "Invalid access token.",
				},
			},
			want: veles.ValidationInvalid,
		},
		{
			name:       "forbidden_other_error",
			statusCode: http.StatusForbidden,
			body: map[string]any{
				"error": map[string]any{
					"name":    "otherError",
					"message": "Some other forbidden error.",
				},
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
			// Create mock collection server
			server := mockCollectionServer(t, validatorTestCollectionKey, tc.statusCode, tc.body)
			defer server.Close()

			// Create client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create validator with mock client
			validator := postmanapikey.NewCollectionValidator(
				postmanapikey.WithClientCollection(client),
			)

			// Create test key
			key := postmanapikey.PostmanCollectionToken{Key: validatorTestCollectionKey}

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

func TestValidatorCollection_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"name":"forbiddenError","message":"You are not authorized to perform this action."}}`))
	}))
	defer server.Close()

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := postmanapikey.NewCollectionValidator(
		postmanapikey.WithClientCollection(client),
	)

	key := postmanapikey.PostmanCollectionToken{Key: validatorTestCollectionKey}

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

func TestValidatorCollection_InvalidRequest(t *testing.T) {
	// For collection validator, a 401 indicates invalid token (no error returned).
	server := mockCollectionServer(t, "", http.StatusUnauthorized, nil)
	defer server.Close()

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := postmanapikey.NewCollectionValidator(
		postmanapikey.WithClientCollection(client),
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
			key:      "invalid-collection-token",
			expected: veles.ValidationInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k := postmanapikey.PostmanCollectionToken{Key: tc.key}

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
