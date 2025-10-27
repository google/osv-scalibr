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

package cratesioapitoken_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/cratesioapitoken"
)

const validatorValidTestKey = "cioAbCdEfGhIjKlMnOpQrStUvWxYz123456"

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if req.URL.Host == "crates.io" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockCratesioServer creates a mock Crates.io API server for testing
func mockCratesioServer(t *testing.T, expectedKey string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a PUT request to the expected crates endpoint
		expectedPath := "/api/v1/crates/osvscalibr"
		if r.Method != http.MethodPut || !strings.HasPrefix(r.URL.Path, expectedPath) {
			t.Errorf("unexpected request: %s %s, expected: PUT %s", r.Method, r.URL.Path, expectedPath)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Authorization header format
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		// Check Authorization
		if authHeader == "Bearer "+expectedKey {
			// Valid token
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[{"detail":"crate velesvalidationtestcrate  does not exist"}]}`))
		} else {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":[{"detail":"authentication failed"}]}`))
			return
		}
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name              string
		key               string
		serverExpectedKey string
		want              veles.ValidationStatus
		expectError       bool
	}{
		{
			name:              "valid_key",
			key:               validatorValidTestKey,
			serverExpectedKey: validatorValidTestKey,
			want:              veles.ValidationValid,
		},
		{
			name:              "invalid_key_unauthorized",
			key:               "random_string",
			serverExpectedKey: validatorValidTestKey[3:],
			want:              veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock server
			server := mockCratesioServer(t, tc.serverExpectedKey)
			defer server.Close()

			// Create a client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create a validator with a mock client
			validator := cratesioapitoken.NewValidator(
				cratesioapitoken.WithClient(client),
			)

			// Create a test key
			key := cratesioapitoken.CratesIOAPItoken{Token: tc.key}

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
	server := mockCratesioServer(t, "Bearer "+validatorValidTestKey)
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := cratesioapitoken.NewValidator(
		cratesioapitoken.WithClient(client),
	)

	key := cratesioapitoken.CratesIOAPItoken{Token: validatorValidTestKey}

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
	// Create a mock server that returns 403 Forbidden for invalid keys
	server := mockCratesioServer(t, "invalid-key")
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := cratesioapitoken.NewValidator(
		cratesioapitoken.WithClient(client),
	)

	testCases := []struct {
		name     string
		key      string
		expected veles.ValidationStatus
	}{
		{
			name:     "empty_key",
			key:      "",
			expected: veles.ValidationFailed,
		},
		{
			name:     "invalid_key_format",
			key:      "invalid-key-format",
			expected: veles.ValidationInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key := cratesioapitoken.CratesIOAPItoken{Token: tc.key}

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
