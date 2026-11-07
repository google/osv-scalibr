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
		if r.Method != http.MethodPost || r.URL.Path != "/v1/oauth2/token" {
			t.Errorf("unexpected request: %s %s, expected: POST /v1/oauth2/token", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		username, password, ok := r.BasicAuth()
		if !ok || username != expectedClientID || password != expectedClientSecret {
			t.Errorf("expected Basic Auth %s:%s, got: %s:%s", expectedClientID, expectedClientSecret, username, password)
		}

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
		wantErr    bool
	}{
		{
			name:       "valid_credentials",
			statusCode: http.StatusOK,
			want:       veles.ValidationValid,
			wantErr:    false,
		},
		{
			name:       "invalid_credentials_unauthorized",
			statusCode: http.StatusUnauthorized,
			want:       veles.ValidationInvalid,
			wantErr:    false,
		},
		{
			// 5xx is indeterminate, not a statement about credential validity.
			name:       "server_error_is_indeterminate",
			statusCode: http.StatusInternalServerError,
			want:       veles.ValidationFailed,
			wantErr:    true,
		},
		{
			// Any other unexpected status is also indeterminate.
			name:       "forbidden_is_indeterminate",
			statusCode: http.StatusForbidden,
			want:       veles.ValidationFailed,
			wantErr:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := mockPayPalTokenServer(t, validatorTestClientID, validatorTestClientSecret, tc.statusCode)
			defer server.Close()

			client := &http.Client{Transport: &mockTransport{testServer: server}}
			validator := paypal.NewValidator()
			validator.HTTPC = client

			creds := paypal.Credentials{
				ID:     validatorTestClientID,
				Secret: validatorTestClientSecret,
			}

			got, err := validator.Validate(t.Context(), creds)
			if tc.wantErr && err == nil {
				t.Errorf("Validate() expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidator_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(nil)
	t.Cleanup(func() { server.Close() })

	client := &http.Client{Transport: &mockTransport{testServer: server}}
	validator := paypal.NewValidator()
	validator.HTTPC = client

	creds := paypal.Credentials{
		ID:     validatorTestClientID,
		Secret: validatorTestClientSecret,
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	got, err := validator.Validate(ctx, creds)
	if diff := cmp.Diff(cmpopts.AnyError, err, cmpopts.EquateErrors()); diff != "" {
		t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}
