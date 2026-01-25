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

package squareapikey_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/squareapikey"
)

const validatorTestToken = "EAAAl-fFiBHM5-4l4faqdYXgciyn9_MoC3hzKh3UfR0WOmrr_o4BOiPK8ZPiUXVs"

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if req.URL.Host == "connect.squareup.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockSquareServer creates a mock Square API server for testing
func mockSquareServer(t *testing.T, expectedToken string, serverResponseCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a GET request to the expected endpoint
		if r.Method != http.MethodGet || r.URL.Path != "/v2/locations" {
			t.Errorf("unexpected request: %s %s, expected: GET /v2/locations", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Authorization header
		authHeader := r.Header.Get("Authorization")
		expectedAuthHeader := "Bearer " + expectedToken
		if len(expectedToken) > 0 && authHeader != expectedAuthHeader {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"errors":[{"category":"AUTHENTICATION_ERROR","code":"UNAUTHORIZED","detail":"This request could not be authorized."}]}`))
			return
		}

		// Check Square-Version header
		squareVersion := r.Header.Get("Square-Version")
		if squareVersion == "" {
			t.Errorf("missing Square-Version header")
		}

		// Set response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(serverResponseCode)
		if serverResponseCode == http.StatusOK {
			_, _ = w.Write([]byte(`{"client_id":"sq0idp-test","token_type":"BEARER","expires_at":"2025-12-31T23:59:59Z","merchant_id":"test-merchant"}`))
		}
	}))
}

func TestPersonalAccessTokenValidator(t *testing.T) {
	cases := []struct {
		name               string
		token              string
		serverExpectedKey  string
		serverResponseCode int
		want               veles.ValidationStatus
		wantErr            error
	}{
		{
			name:               "valid_token",
			token:              validatorTestToken,
			serverExpectedKey:  validatorTestToken,
			serverResponseCode: http.StatusOK,
			want:               veles.ValidationValid,
		},
		{
			name:               "invalid_token_unauthorized",
			token:              "EAAAinvalidtokeninvalidtokeninvalidtokeninvalidtokeninvalid",
			serverExpectedKey:  validatorTestToken,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "server_error",
			token:              validatorTestToken,
			serverExpectedKey:  validatorTestToken,
			serverResponseCode: http.StatusInternalServerError,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
		{
			name:               "bad_gateway",
			token:              validatorTestToken,
			serverExpectedKey:  validatorTestToken,
			serverResponseCode: http.StatusBadGateway,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
		{
			name:               "forbidden",
			token:              validatorTestToken,
			serverExpectedKey:  validatorTestToken,
			serverResponseCode: http.StatusForbidden,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock server
			server := mockSquareServer(t, tc.serverExpectedKey, tc.serverResponseCode)
			defer server.Close()

			// Create a client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create a validator with a mock client
			validator := squareapikey.NewPersonalAccessTokenValidator()
			validator.HTTPC = client

			// Create a test token
			token := squareapikey.SquarePersonalAccessToken{Key: tc.token}

			// Test validation
			got, err := validator.Validate(t.Context(), token)

			if !cmp.Equal(tc.wantErr, err, cmpopts.EquateErrors()) {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			// Check validation status
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPersonalAccessTokenValidator_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"client_id":"sq0idp-test","token_type":"BEARER"}`))
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := squareapikey.NewPersonalAccessTokenValidator()
	validator.HTTPC = client

	token := squareapikey.SquarePersonalAccessToken{Key: validatorTestToken}

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

func TestPersonalAccessTokenValidator_InvalidRequest(t *testing.T) {
	// Create a mock server that returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := squareapikey.NewPersonalAccessTokenValidator()
	validator.HTTPC = client

	testCases := []struct {
		name     string
		token    string
		expected veles.ValidationStatus
	}{
		{
			name:     "empty_token",
			token:    "",
			expected: veles.ValidationInvalid,
		},
		{
			name:     "invalid_token_format",
			token:    "EAAABinvalidtoken",
			expected: veles.ValidationInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := squareapikey.SquarePersonalAccessToken{Key: tc.token}

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

func TestPersonalAccessTokenValidator_AuthorizationHeader(t *testing.T) {
	// Test that the Authorization header is correctly formatted
	var capturedAuthHeader string
	var capturedSquareVersion string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuthHeader = r.Header.Get("Authorization")
		capturedSquareVersion = r.Header.Get("Square-Version")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"client_id":"sq0idp-test","token_type":"BEARER"}`))
	}))
	defer server.Close()

	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := squareapikey.NewPersonalAccessTokenValidator()
	validator.HTTPC = client

	token := squareapikey.SquarePersonalAccessToken{Key: validatorTestToken}

	_, err := validator.Validate(t.Context(), token)
	if err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}

	expectedPrefix := "Bearer "
	if !strings.HasPrefix(capturedAuthHeader, expectedPrefix) {
		t.Errorf("Authorization header = %q, want prefix %q", capturedAuthHeader, expectedPrefix)
	}

	if !strings.Contains(capturedAuthHeader, validatorTestToken) {
		t.Errorf("Authorization header = %q, want to contain token %q", capturedAuthHeader, validatorTestToken)
	}

	if capturedSquareVersion == "" {
		t.Errorf("Square-Version header is empty, expected a version string")
	}
}

func TestOAuthApplicationSecretValidator(t *testing.T) {
	cases := []struct {
		name               string
		id                 string
		secret             string
		serverResponseCode int
		want               veles.ValidationStatus
		wantErr            error
	}{
		{
			name:               "valid_credentials_with_404",
			id:                 "sq0idp-wuPhZFY8etbvhybDEdHllQ",
			secret:             "sq0csp-aebm-dWBi74tX5f-LQQ-pC5x3WtHg7jVajqTijTM0xc",
			serverResponseCode: http.StatusNotFound, // 404 means valid credentials
			want:               veles.ValidationValid,
		},
		{
			name:               "valid_credentials_with_200",
			id:                 "sq0idp-wuPhZFY8etbvhybDEdHllQ",
			secret:             "sq0csp-aebm-dWBi74tX5f-LQQ-pC5x3WtHg7jVajqTijTM0xc",
			serverResponseCode: http.StatusOK, // 200 means valid credentials (unlikely with random token)
			want:               veles.ValidationValid,
		},
		{
			name:               "invalid_credentials",
			id:                 "sq0idp-wuPhZFY8etbvhybDEdHllQ",
			secret:             "sq0csp-INVALID_SECRET_INVALID_SECRET_INVALID",
			serverResponseCode: http.StatusUnauthorized, // 401 means invalid credentials
			want:               veles.ValidationInvalid,
		},
		{
			name:               "server_error",
			id:                 "sq0idp-wuPhZFY8etbvhybDEdHllQ",
			secret:             "sq0csp-aebm-dWBi74tX5f-LQQ-pC5x3WtHg7jVajqTijTM0xc",
			serverResponseCode: http.StatusInternalServerError,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
		{
			name:    "missing_id",
			id:      "",
			secret:  "sq0csp-aebm-dWBi74tX5f-LQQ-pC5x3WtHg7jVajqTijTM0xc",
			want:    veles.ValidationFailed,
			wantErr: cmpopts.AnyError,
		},
		{
			name:    "missing_secret",
			id:      "sq0idp-wuPhZFY8etbvhybDEdHllQ",
			secret:  "",
			want:    veles.ValidationFailed,
			wantErr: cmpopts.AnyError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock server for OAuth validation
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Check if it's a POST request to the expected endpoint
				if r.Method != http.MethodPost || r.URL.Path != "/oauth2/revoke" {
					t.Errorf("unexpected request: %s %s, expected: POST /oauth2/revoke", r.Method, r.URL.Path)
					http.Error(w, "not found", http.StatusNotFound)
					return
				}

				// Check Authorization header format
				authHeader := r.Header.Get("Authorization")
				if !strings.HasPrefix(authHeader, "Client ") {
					t.Errorf("Authorization header = %q, want prefix 'Client '", authHeader)
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.serverResponseCode)

				// Write appropriate response body based on status code
				if tc.serverResponseCode == http.StatusNotFound {
					_, _ = w.Write([]byte(`{"errors":[{"code":"NOT_FOUND","detail":"access token not found"}]}`))
				} else if tc.serverResponseCode == http.StatusUnauthorized {
					_, _ = w.Write([]byte(`{"message":"Not Authorized","type":"service.not_authorized"}`))
				}
			}))
			defer server.Close()

			// Create a client with custom transport
			client := &http.Client{
				Transport: &mockOAuthTransport{testServer: server},
			}

			// Create a validator with a mock client
			validator := squareapikey.NewOAuthApplicationSecretValidator()
			validator.HTTPC = client

			// Create test credentials
			creds := squareapikey.SquareOAuthApplicationSecret{
				ID:  tc.id,
				Key: tc.secret,
			}

			// Test validation
			got, err := validator.Validate(t.Context(), creds)

			if !cmp.Equal(tc.wantErr, err, cmpopts.EquateErrors()) {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			// Check validation status
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

// mockOAuthTransport redirects OAuth requests to the test server
type mockOAuthTransport struct {
	testServer *httptest.Server
}

func (m *mockOAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if req.URL.Host == "connect.squareup.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}
