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

package elasticcloudapikey_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/elasticcloudapikey"
)

const validatorTestKey = "essu_VWtSQlNXNWFjMEpWWVZsbFVUZDBORmRQTldJNmNuWnVYMU5yY1ZGdlJ6aHVlRE5rWmxGelIyUk9kdz09AAAAANx5Zs4="

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if req.URL.Host == "api.elastic-cloud.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockElasticCloudServer creates a mock Elastic Cloud API server for testing
func mockElasticCloudServer(t *testing.T, expectedKey string, serverResponseCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a GET request to the expected endpoint
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/account" {
			t.Errorf("unexpected request: %s %s, expected: GET /api/v1/account", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Authorization header
		authHeader := r.Header.Get("Authorization")
		expectedAuthHeader := "ApiKey " + expectedKey
		if len(expectedKey) > 0 && authHeader != expectedAuthHeader {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Set response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(serverResponseCode)
		if serverResponseCode == http.StatusOK {
			_, _ = w.Write([]byte(`{"user":{"id":"test-user"}}`))
		}
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
			serverResponseCode: http.StatusOK,
			want:               veles.ValidationValid,
		},
		{
			name:               "invalid_key_unauthorized",
			key:                "essu_invalidkeyinvalidkeyinvalidkeyinvalidkeyinvalidkeyinvalidkeyinvalidkeyinvalidkey123=",
			serverExpectedKey:  validatorTestKey,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "server_error",
			key:                validatorTestKey,
			serverExpectedKey:  validatorTestKey,
			serverResponseCode: http.StatusInternalServerError,
			want:               veles.ValidationFailed,
			expectError:        true,
		},
		{
			name:               "bad_gateway",
			key:                validatorTestKey,
			serverExpectedKey:  validatorTestKey,
			serverResponseCode: http.StatusBadGateway,
			want:               veles.ValidationFailed,
			expectError:        true,
		},
		{
			name:               "forbidden",
			key:                validatorTestKey,
			serverExpectedKey:  validatorTestKey,
			serverResponseCode: http.StatusForbidden,
			want:               veles.ValidationFailed,
			expectError:        true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock server
			server := mockElasticCloudServer(t, tc.serverExpectedKey, tc.serverResponseCode)
			defer server.Close()

			// Create a client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create a validator with a mock client
			validator := elasticcloudapikey.NewValidator()
			validator.HTTPC = client

			// Create a test key
			key := elasticcloudapikey.ElasticCloudAPIKey{Key: tc.key}

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
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"user":{"id":"test-user"}}`))
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := elasticcloudapikey.NewValidator()
	validator.HTTPC = client

	key := elasticcloudapikey.ElasticCloudAPIKey{Key: validatorTestKey}

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

	validator := elasticcloudapikey.NewValidator()
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
			key := elasticcloudapikey.ElasticCloudAPIKey{Key: tc.key}

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

func TestValidator_AuthorizationHeader(t *testing.T) {
	// Test that the Authorization header is correctly formatted
	var capturedAuthHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"user":{"id":"test-user"}}`))
	}))
	defer server.Close()

	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := elasticcloudapikey.NewValidator()
	validator.HTTPC = client

	key := elasticcloudapikey.ElasticCloudAPIKey{Key: validatorTestKey}

	_, err := validator.Validate(t.Context(), key)
	if err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}

	expectedPrefix := "ApiKey "
	if !strings.HasPrefix(capturedAuthHeader, expectedPrefix) {
		t.Errorf("Authorization header = %q, want prefix %q", capturedAuthHeader, expectedPrefix)
	}

	if !strings.Contains(capturedAuthHeader, validatorTestKey) {
		t.Errorf("Authorization header = %q, want to contain key %q", capturedAuthHeader, validatorTestKey)
	}
}
