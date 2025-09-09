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

package stripeapikey_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/osv-scalibr/veles"
	stripeapikey "github.com/google/osv-scalibr/veles/secrets/stripeapikey"
)

const (
	validatorTestKeySK = "sk_test_51234567890123456789012345678901234567890123456789012345678901234"
	validatorLiveKeySK = "sk_live_51234567890123456789012345678901234567890123456789012345678901234"
	validatorTestKeyRK = "rk_test_51234567890123456789012345678901234567890123456789012345678901234"
	validatorLiveKeyRK = "rk_live_51234567890123456789012345678901234567890123456789012345678901234"
)

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if req.URL.Host == "api.stripe.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockStripeServer creates a mock Stripe API server for testing
func mockStripeServer(t *testing.T, expectedKey string, statusCode int, responseBody string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a GET request to the expected endpoint
		if r.Method != http.MethodGet || r.URL.Path != "/v1/accounts" {
			t.Errorf("unexpected request: %s %s, expected: GET /v1/accounts", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Basic Auth
		username, _, ok := r.BasicAuth()
		if !ok || username != expectedKey {
			t.Errorf("expected Basic Auth username %s, got: %s (ok: %v)", expectedKey, username, ok)
		}

		// Set response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if responseBody != "" {
			w.Write([]byte(responseBody))
		}
	}))
}

// Test cases for SK validators
func TestValidatorSKTest(t *testing.T) {
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
			name:       "invalid_key_forbidden",
			statusCode: http.StatusForbidden,
			want:       veles.ValidationInvalid,
		},
		{
			name:       "server_error",
			statusCode: http.StatusInternalServerError,
			want:       veles.ValidationFailed,
		},
		{
			name:        "bad_gateway",
			statusCode:  http.StatusBadGateway,
			want:        veles.ValidationFailed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server
			server := mockStripeServer(t, validatorTestKeySK, tc.statusCode, "")
			defer server.Close()

			// Create client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create validator with mock client
			validator := stripeapikey.NewValidatorSKTest(
				stripeapikey.WithClientSK(client),
			)

			// Create test key
			key := stripeapikey.StripeSKTestKey{Key: validatorTestKeySK}

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

func TestValidatorSKLive(t *testing.T) {
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
			name:       "invalid_key_forbidden",
			statusCode: http.StatusForbidden,
			want:       veles.ValidationInvalid,
		},
		{
			name:        "server_error",
			statusCode:  http.StatusInternalServerError,
			want:        veles.ValidationFailed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server
			server := mockStripeServer(t, validatorLiveKeySK, tc.statusCode, "")
			defer server.Close()

			// Create client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create validator with mock client
			validator := stripeapikey.NewValidatorSKLive(
				stripeapikey.WithClientSK(client),
			)

			// Create test key
			key := stripeapikey.StripeSKLiveKey{Key: validatorLiveKeySK}

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

// Test cases for RK validators
func TestValidatorRKTest(t *testing.T) {
	permissionErrorResponse := `{"error":{"message":"This API key does not have the required permissions for this operation."}}`
	otherErrorResponse := `{"error":{"message":"Invalid API key provided"}}`

	cases := []struct {
		name         string
		statusCode   int
		responseBody string
		want         veles.ValidationStatus
		expectError  bool
	}{
		{
			name:       "valid_key_full_access",
			statusCode: http.StatusOK,
			want:       veles.ValidationValid,
		},
		{
			name:         "valid_key_scoped_permissions",
			statusCode:   http.StatusForbidden,
			responseBody: permissionErrorResponse,
			want:         veles.ValidationValid,
		},
		{
			name:         "invalid_key_forbidden_other_reason",
			statusCode:   http.StatusForbidden,
			responseBody: otherErrorResponse,
			want:         veles.ValidationInvalid,
		},
		{
			name:       "invalid_key_unauthorized",
			statusCode: http.StatusUnauthorized,
			want:       veles.ValidationInvalid,
		},
		{
			name:        "server_error",
			statusCode:  http.StatusInternalServerError,
			want:        veles.ValidationFailed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server
			server := mockStripeServer(t, validatorTestKeyRK, tc.statusCode, tc.responseBody)
			defer server.Close()

			// Create client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create validator with mock client
			validator := stripeapikey.NewValidatorRKTest(
				stripeapikey.WithClientRK(client),
			)

			// Create test key
			key := stripeapikey.StripeRKTestKey{Key: validatorTestKeyRK}

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

func TestValidatorRKLive(t *testing.T) {
	permissionErrorResponse := `{"error":{"message":"This API key does not have the required permissions for this operation."}}`
	
	cases := []struct {
		name         string
		statusCode   int
		responseBody string
		want         veles.ValidationStatus
		expectError  bool
	}{
		{
			name:       "valid_key_full_access",
			statusCode: http.StatusOK,
			want:       veles.ValidationValid,
		},
		{
			name:         "valid_key_scoped_permissions",
			statusCode:   http.StatusForbidden,
			responseBody: permissionErrorResponse,
			want:         veles.ValidationValid,
		},
		{
			name:       "invalid_key_unauthorized",
			statusCode: http.StatusUnauthorized,
			want:       veles.ValidationInvalid,
		},
		{
			name:        "server_error",
			statusCode:  http.StatusInternalServerError,
			want:        veles.ValidationFailed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server
			server := mockStripeServer(t, validatorLiveKeyRK, tc.statusCode, tc.responseBody)
			defer server.Close()

			// Create client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create validator with mock client
			validator := stripeapikey.NewValidatorRKLive(
				stripeapikey.WithClientRK(client),
			)

			// Create test key
			key := stripeapikey.StripeRKLiveKey{Key: validatorLiveKeyRK}

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

// Test context cancellation for SK validators
func TestValidatorSK_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := stripeapikey.NewValidatorSKTest(
		stripeapikey.WithClientSK(client),
	)

	key := stripeapikey.StripeSKTestKey{Key: validatorTestKeySK}

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

// Test context cancellation for RK validators
func TestValidatorRK_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := stripeapikey.NewValidatorRKTest(
		stripeapikey.WithClientRK(client),
	)

	key := stripeapikey.StripeRKTestKey{Key: validatorTestKeyRK}

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

// Test invalid request scenarios
func TestValidatorSK_InvalidRequest(t *testing.T) {
	// Create mock server that returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := stripeapikey.NewValidatorSKTest(
		stripeapikey.WithClientSK(client),
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
			key := stripeapikey.StripeSKTestKey{Key: tc.key}

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

func TestValidatorRK_InvalidRequest(t *testing.T) {
	// Create mock server that returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := stripeapikey.NewValidatorRKTest(
		stripeapikey.WithClientRK(client),
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
			key := stripeapikey.StripeRKTestKey{Key: tc.key}

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

// Test RK validator JSON parsing error
func TestValidatorRK_JSONParsingError(t *testing.T) {
	// Create mock server that returns 403 with invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("invalid json response"))
	}))
	defer server.Close()

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := stripeapikey.NewValidatorRKTest(
		stripeapikey.WithClientRK(client),
	)

	key := stripeapikey.StripeRKTestKey{Key: validatorTestKeyRK}

	got, err := validator.Validate(context.Background(), key)

	if err == nil {
		t.Errorf("Validate() expected error due to JSON parsing failure, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
	if !strings.Contains(err.Error(), "parse 403") {
		t.Errorf("Expected error to contain 'parse 403', got: %v", err)
	}
}