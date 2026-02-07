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

// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stripeapikeys_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	stripeapikeys "github.com/google/osv-scalibr/veles/secrets/stripeapikeys"
)

const (
	validatorTestSK = "sk_live_51PvZzqABcD1234EfGhIjKlMnOpQrStUvWxYz0123456789abcdefghijklmnopQRSTuvWXYZabcd12345678"
	validatorTestRK = "rk_live_51PvZzABcDEfGhIjKlMnOpQrStUvWxYz0123456789abcdefGHIJKLMNOPQRSTUVWXYZabcd12345678"
)

// mockTransport redirects requests to the test server for the configured hosts.
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL for Stripe API hosts.
	if req.URL.Host == "api.stripe.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockStripeAPIServer creates a mock Stripe /v1/accounts endpoint for testing validators.
func mockStripeAPIServer(t *testing.T, expectedKey string, statusCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Expect a GET to /v1/accounts
		if r.Method != http.MethodGet || r.URL.Path != "/v1/accounts" {
			t.Errorf("unexpected request: %s %s, expected: GET /v1/accounts", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Basic Auth header contains the expected key
		username, _, ok := r.BasicAuth()
		if !ok || username != expectedKey {
			t.Errorf("expected Basic Auth username to be %s, got: %s", expectedKey, username)
		}

		w.WriteHeader(statusCode)
	}))
}

func TestValidatorSecretKey(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		want       veles.ValidationStatus
		wantErr    error
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
			name:       "server_error",
			statusCode: http.StatusInternalServerError,
			want:       veles.ValidationInvalid,
		},
		{
			name:       "forbidden_error",
			statusCode: http.StatusForbidden,
			want:       veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server
			server := mockStripeAPIServer(t, validatorTestSK, tc.statusCode)
			defer server.Close()

			// Create client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create validator with mock client
			validator := stripeapikeys.NewSecretKeyValidator()
			validator.HTTPC = client

			// Create test key
			key := stripeapikeys.StripeSecretKey{Key: validatorTestSK}

			// Test validation
			got, err := validator.Validate(t.Context(), key)

			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
			}

			// Check validation status
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidatorSecretKey_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(nil)
	t.Cleanup(func() {
		server.Close()
	})

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := stripeapikeys.NewSecretKeyValidator()
	validator.HTTPC = client

	key := stripeapikeys.StripeSecretKey{Key: validatorTestSK}

	// Create context that is immediately cancelled
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Test validation with cancelled context
	got, err := validator.Validate(ctx, key)

	if diff := cmp.Diff(cmpopts.AnyError, err, cmpopts.EquateErrors()); diff != "" {
		t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}

func TestValidatorRestrictedKey(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		want       veles.ValidationStatus
		wantErr    error
	}{
		{
			name:       "valid_key_ok",
			statusCode: http.StatusOK,
			want:       veles.ValidationValid,
		},
		{
			name:       "valid_key_forbidden",
			statusCode: http.StatusForbidden,
			want:       veles.ValidationValid,
		},
		{
			name:       "invalid_key_unauthorized",
			statusCode: http.StatusUnauthorized,
			want:       veles.ValidationInvalid,
		},
		{
			name:       "server_error",
			statusCode: http.StatusInternalServerError,
			want:       veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server
			server := mockStripeAPIServer(t, validatorTestRK, tc.statusCode)
			defer server.Close()

			// Create client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create validator with mock client
			validator := stripeapikeys.NewRestrictedKeyValidator()
			validator.HTTPC = client

			// Create test key
			key := stripeapikeys.StripeRestrictedKey{Key: validatorTestRK}

			// Test validation
			got, err := validator.Validate(t.Context(), key)

			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
			}

			// Check validation status
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidatorRestrictedKey_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(nil)
	t.Cleanup(func() {
		server.Close()
	})

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := stripeapikeys.NewRestrictedKeyValidator()
	validator.HTTPC = client

	key := stripeapikeys.StripeRestrictedKey{Key: validatorTestRK}

	// Create context that is immediately cancelled
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Test validation with cancelled context
	got, err := validator.Validate(ctx, key)

	if diff := cmp.Diff(cmpopts.AnyError, err, cmpopts.EquateErrors()); diff != "" {
		t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}
