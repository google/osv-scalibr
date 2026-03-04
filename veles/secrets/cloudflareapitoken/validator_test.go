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

package cloudflareapitoken_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/cloudflareapitoken"
)

const validatorTestToken = "7awgM4jG5SQvxcvmNzhKj8PQjxo7awgM4jG5SQv"

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if req.URL.Host == "api.cloudflare.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockCloudflareServer creates a mock Cloudflare API server for testing
func mockCloudflareServer(t *testing.T, expectedToken string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a GET request to the expected endpoint
		if r.Method != http.MethodGet ||
			r.URL.Path != "/client/v4/zones" {
			t.Errorf("unexpected request: %s %s, expected: GET /client/v4/zones", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Authorization header
		authHeader := r.Header.Get("Authorization")
		expectedAuth := "Bearer " + expectedToken
		if authHeader != expectedAuth {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name  string
		Token string
		want  veles.ValidationStatus
	}{
		{
			name:  "invalid token",
			Token: "invalid_token_7awgM4jG5SQvxcvmNzhKj8P",
			want:  veles.ValidationInvalid,
		},
		{
			name:  "valid token",
			Token: validatorTestToken,
			want:  veles.ValidationValid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock server
			server := mockCloudflareServer(t, validatorTestToken)
			defer server.Close()

			// Create a client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create a validator with a mock client
			validator := cloudflareapitoken.NewValidator()
			validator.HTTPC = client

			// Create a test token
			token := cloudflareapitoken.CloudflareAPIToken{Token: tc.Token}

			// Test validation
			got, err := validator.Validate(t.Context(), token)

			if !cmp.Equal(err, nil, cmpopts.EquateErrors()) {
				t.Fatalf("plugin.Validate(%v) got error: %v\n", token, err)
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

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := cloudflareapitoken.NewValidator()
	validator.HTTPC = client

	// Create a test token
	token := cloudflareapitoken.CloudflareAPIToken{Token: validatorTestToken}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Test validation with cancelled context
	got, err := validator.Validate(ctx, token)

	if err == nil {
		t.Errorf("Validate() expected error due to context cancellation, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}

func TestValidator_InvalidRequest(t *testing.T) {
	// Create a mock server that returns 403 Forbidden
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := cloudflareapitoken.NewValidator()
	validator.HTTPC = client

	testCases := []struct {
		name     string
		Token    string
		expected veles.ValidationStatus
	}{
		{
			name:     "empty_token",
			Token:    "",
			expected: veles.ValidationInvalid,
		},
		{
			name:     "invalid_token_format",
			Token:    "invalid-token-format",
			expected: veles.ValidationInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := cloudflareapitoken.CloudflareAPIToken{Token: tc.Token}

			got, err := validator.Validate(t.Context(), token)

			if err != nil {
				t.Errorf("Validate() unexpected error for %s: %v", tc.name, err)
			}
			if got != tc.expected {
				t.Errorf("Validate() = %v, want %v for %s", got, tc.expected, tc.name)
			}
		})
	}
}
