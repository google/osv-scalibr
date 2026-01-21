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

package salesforceoauth2access_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/salesforceoauth2access"
)

const (
	validatorTestToken = "00D123456789!AB_CDEF.ABC123456789ABC123456789ABC12ABC123456789ABC123456789ABC12"
)

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if req.URL.Host == "login.salesforce.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockPaystackServer creates a mock PayStack API server for testing
func mockPaystackServer(t *testing.T, expectedToken string, statusCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a GET request to the expected endpoint
		if r.Method != http.MethodGet || r.URL.Path != "/services/oauth2/userinfo" {
			t.Errorf("unexpected request: %s %s, expected: GET /customer", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Basic Auth header contains the expected key
		authHeader := r.Header.Get("Authorization")
		if !strings.Contains(authHeader, expectedToken) {
			t.Errorf("expected Bearer token to be Bearer %s, got: %s", expectedToken, authHeader)
		}

		w.WriteHeader(statusCode)
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name          string
		statusCode    int
		cancelContext bool
		want          veles.ValidationStatus
		expectError   bool
	}{
		{
			name:       "valid_token",
			statusCode: http.StatusOK,
			want:       veles.ValidationValid,
		},
		{
			name:       "invalid_token_unauthorized",
			statusCode: http.StatusUnauthorized,
			want:       veles.ValidationInvalid,
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
		{
			name:          "context cancelled",
			statusCode:    http.StatusInternalServerError,
			cancelContext: true,
			want:          veles.ValidationFailed,
			expectError:   true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			// Create mock server
			server := mockPaystackServer(t, validatorTestToken, tt.statusCode)
			defer server.Close()

			if tt.cancelContext {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			validator := salesforceoauth2access.NewValidator()
			if server != nil {
				validator.HTTPC = &http.Client{
					Transport: &mockTransport{testServer: server},
				}
			}

			// Create test token
			token := salesforceoauth2access.Token{Token: validatorTestToken}

			// Test validation
			got, err := validator.Validate(ctx, token)

			if tt.expectError && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}
