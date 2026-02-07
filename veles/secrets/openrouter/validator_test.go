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

package openrouter_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/openrouter"
)

const validatorTestKey = "sk-or-v1-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqr"

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if req.URL.Host == "openrouter.ai" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockOpenRouterServer creates a mock OpenRouter API server for testing
func mockOpenRouterServer(t *testing.T, expectedKey string, statusCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a GET request to the expected endpoint
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/auth/key" {
			t.Errorf("unexpected request: %s %s, expected: GET /api/v1/auth/key", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Authorization header
		authHeader := r.Header.Get("Authorization")
		if !strings.HasSuffix(authHeader, expectedKey) {
			t.Errorf("expected Authorization header to end with key %s, got: %s", expectedKey, authHeader)
		}

		// Set response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name        string
		statusCode  int
		want        veles.ValidationStatus
		expectError bool
	}{
		{
			name:       "valid_key",
			statusCode: http.StatusOK,
			want:       veles.ValidationValid,
		},
		{
			name:       "invalid_key_unauthorized",
			statusCode: http.StatusUnauthorized,
			want:       veles.ValidationInvalid,
		},
		{
			name:       "rate_limited_but_likely_valid",
			statusCode: http.StatusTooManyRequests,
			want:       veles.ValidationValid,
		},
		{
			name:        "server_error",
			statusCode:  http.StatusInternalServerError,
			want:        veles.ValidationFailed,
			expectError: true,
		},
		{
			name:        "bad_gateway",
			statusCode:  http.StatusBadGateway,
			want:        veles.ValidationFailed,
			expectError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server
			server := mockOpenRouterServer(t, validatorTestKey, tc.statusCode)
			defer server.Close()

			// Create client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create validator with mock client
			validator := openrouter.NewValidator()
			validator.HTTPC = client

			// Create test key
			key := openrouter.APIKey{Key: validatorTestKey}

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

func TestValidator_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := openrouter.NewValidator()
	validator.HTTPC = client

	key := openrouter.APIKey{Key: validatorTestKey}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

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
	// Create mock server that returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := openrouter.NewValidator()
	validator.HTTPC = client

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
			key := openrouter.APIKey{Key: tc.key}

			got, err := validator.Validate(context.Background(), key)

			if err != nil {
				t.Errorf("Validate() unexpected error for %s: %v", tc.name, err)
			}
			if got != tc.expected {
				t.Errorf("Validate() = %v, want %v for %s", got, tc.expected, tc.name)
			}
		})
	}
}
