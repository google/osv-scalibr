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

package nugetorgapikey_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/nugetorgapikey"
)

const validatorTestKey = "oy2a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v"

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if req.URL.Host == "www.nuget.org" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockNuGetServer creates a mock NuGet API server for testing
func mockNuGetServer(t *testing.T, expectedKey string, serverResponseCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a PUT request to the expected endpoint
		if r.Method != http.MethodPut || r.URL.Path != "/api/v2/package" {
			t.Errorf("unexpected request: %s %s, expected: PUT /api/v2/package", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check X-Nuget-Apikey header
		apiKey := r.Header.Get("X-Nuget-Apikey")
		if apiKey != expectedKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Set response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(serverResponseCode)
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name               string
		key                string
		serverExpectedKey  string
		serverResponseCode int
		want               veles.ValidationStatus
		expectError        bool
	}{
		{
			name:               "valid_key",
			key:                validatorTestKey,
			serverExpectedKey:  validatorTestKey,
			serverResponseCode: http.StatusBadRequest,
			want:               veles.ValidationValid,
		},
		{
			name:               "invalid_key_unauthorized",
			key:                "random_string",
			serverExpectedKey:  validatorTestKey,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "invalid_key_forbidden",
			key:                "random_string",
			serverExpectedKey:  validatorTestKey,
			serverResponseCode: http.StatusForbidden,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "server_error",
			serverResponseCode: http.StatusInternalServerError,
			want:               veles.ValidationFailed,
			expectError:        true,
		},
		{
			name:               "bad_gateway",
			serverResponseCode: http.StatusBadGateway,
			want:               veles.ValidationFailed,
			expectError:        true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock server
			server := mockNuGetServer(t, tc.serverExpectedKey, tc.serverResponseCode)
			defer server.Close()

			// Create a client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create a validator with a mock client
			validator := nugetorgapikey.NewValidator()
			validator.HTTPC = client

			// Create a test key
			key := nugetorgapikey.NuGetOrgAPIKey{Token: tc.key}

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

func TestValidator_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := nugetorgapikey.NewValidator()
	validator.HTTPC = client

	key := nugetorgapikey.NuGetOrgAPIKey{Token: validatorTestKey}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(t.Context())
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
	// Create a mock server that returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := nugetorgapikey.NewValidator()
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
			key := nugetorgapikey.NuGetOrgAPIKey{Token: tc.key}

			got, err := validator.Validate(t.Context(), key)

			if err != nil {
				t.Errorf("Validate() unexpected error for %s: %v", tc.name, err)
			}
			if got != tc.expected {
				t.Errorf("Validate() = %v, want %v for %s", got, tc.expected, tc.name)
			}
		})
	}
}
