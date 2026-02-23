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

package paypal_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/paypal"
)

const (
	validatorTestClientID     = "AYSq3RDGsmBLJE-otTkBtM-jBRd1TCQwFf9RGfwddNXWz0uFU9ztymylOhRSAbCdEf01234567890"
	validatorTestClientSecret = "EGnHDxD_qRPdaLdZz8iKr8N7_MzF-YHPTkjs6NKYQvQSBngp4PTTVWkPZRbLOhRSAbCdEf01234567890"
)

// mockTransport redirects requests to the test server for PayPal API hosts.
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL for PayPal API hosts.
	if req.URL.Host == "api-m.paypal.com" || req.URL.Host == "api-m.sandbox.paypal.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockPayPalTokenServer creates a mock PayPal /v1/oauth2/token endpoint.
func mockPayPalTokenServer(t *testing.T, expectedClientID, expectedClientSecret string, statusCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Expect a POST to /v1/oauth2/token.
		if r.Method != http.MethodPost || r.URL.Path != "/v1/oauth2/token" {
			t.Errorf("unexpected request: %s %s, expected: POST /v1/oauth2/token", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Basic Auth header contains the expected credentials.
		username, password, ok := r.BasicAuth()
		if !ok || username != expectedClientID || password != expectedClientSecret {
			t.Errorf("expected Basic Auth %s:%s, got: %s:%s", expectedClientID, expectedClientSecret, username, password)
		}

		// Check Content-Type.
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("expected Content-Type application/x-www-form-urlencoded, got: %s", ct)
		}

		w.WriteHeader(statusCode)
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		want       veles.ValidationStatus
	}{
		{
			name:       "valid_credentials",
			statusCode: http.StatusOK,
			want:       veles.ValidationValid,
		},
		{
			name:       "invalid_credentials_unauthorized",
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
			// Create mock server.
			server := mockPayPalTokenServer(t, validatorTestClientID, validatorTestClientSecret, tc.statusCode)
			defer server.Close()

			// Create client with custom transport.
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create validator with mock client.
			validator := paypal.NewValidator()
			validator.HTTPC = client

			// Create test credential pair.
			pair := paypal.ClientIDSecretPair{
				ClientID:     validatorTestClientID,
				ClientSecret: validatorTestClientSecret,
			}

			// Test validation.
			got, err := validator.Validate(t.Context(), pair)

			if err != nil {
				t.Errorf("Validate(): %v", err)
			}

			// Check validation status.
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidator_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(nil)
	t.Cleanup(func() {
		server.Close()
	})

	// Create client with custom transport.
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := paypal.NewValidator()
	validator.HTTPC = client

	pair := paypal.ClientIDSecretPair{
		ClientID:     validatorTestClientID,
		ClientSecret: validatorTestClientSecret,
	}

	// Create context that is immediately cancelled.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Test validation with cancelled context.
	got, err := validator.Validate(ctx, pair)

	if diff := cmp.Diff(cmpopts.AnyError, err, cmpopts.EquateErrors()); diff != "" {
		t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}
