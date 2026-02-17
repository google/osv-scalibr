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

package bitwardenoauth2access_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/bitwardenoauth2access"
)

const (
	validatorTestClientID     = "d351d93b-adb0-4714-bbef-a11100fff9cc"
	validatorTestClientSecret = "N8N2xWg4FV8lusbl5CHBb5XRil6kOa"
)

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if req.URL.Host == "identity.bitwarden.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockBitwardenServer creates a mock Bitwarden identity server for testing
func mockBitwardenServer(t *testing.T, expectedClientID, expectedClientSecret string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a POST request to the expected endpoint
		if r.Method != http.MethodPost || r.URL.Path != "/connect/token" {
			t.Errorf("unexpected request: %s %s, expected: POST /connect/token", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Content-Type header
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/x-www-form-urlencoded" {
			t.Errorf("unexpected Content-Type: %s", contentType)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Parse form data
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Validate client credentials
		clientID := r.FormValue("client_id")
		clientSecret := r.FormValue("client_secret")
		grantType := r.FormValue("grant_type")

		if grantType != "client_credentials" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if clientID == "user."+expectedClientID && clientSecret == expectedClientSecret {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"test_token","token_type":"Bearer"}`))
			return
		}

		w.WriteHeader(http.StatusBadRequest)
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name         string
		clientID     string
		clientSecret string
		want         veles.ValidationStatus
	}{
		{
			name:         "valid credentials",
			clientID:     validatorTestClientID,
			clientSecret: validatorTestClientSecret,
			want:         veles.ValidationValid,
		},
		{
			name:         "invalid client secret",
			clientID:     validatorTestClientID,
			clientSecret: "invalid_secret_1234567890",
			want:         veles.ValidationInvalid,
		},
		{
			name:         "invalid client ID",
			clientID:     "00000000-0000-0000-0000-000000000000",
			clientSecret: validatorTestClientSecret,
			want:         veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock server
			server := mockBitwardenServer(t, validatorTestClientID, validatorTestClientSecret)
			defer server.Close()

			// Create a client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create a validator with a mock client
			validator := bitwardenoauth2access.NewValidator()
			validator.HTTPC = client

			// Create a test token
			token := bitwardenoauth2access.Token{
				ClientID:     tc.clientID,
				ClientSecret: tc.clientSecret,
			}

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
	// Create a server that responds OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := bitwardenoauth2access.NewValidator()
	validator.HTTPC = client

	// Create a test token
	token := bitwardenoauth2access.Token{
		ClientID:     validatorTestClientID,
		ClientSecret: validatorTestClientSecret,
	}

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
	// Create a mock server that returns 400 Bad Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := bitwardenoauth2access.NewValidator()
	validator.HTTPC = client

	testCases := []struct {
		name     string
		token    bitwardenoauth2access.Token
		expected veles.ValidationStatus
	}{
		{
			name: "empty credentials",
			token: bitwardenoauth2access.Token{
				ClientID:     "",
				ClientSecret: "",
			},
			expected: veles.ValidationInvalid,
		},
		{
			name: "invalid format credentials",
			token: bitwardenoauth2access.Token{
				ClientID:     "not-a-uuid",
				ClientSecret: "invalid",
			},
			expected: veles.ValidationInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validator.Validate(t.Context(), tc.token)

			if err != nil {
				t.Errorf("Validate() unexpected error for %s: %v", tc.name, err)
			}
			if got != tc.expected {
				t.Errorf("Validate() = %v, want %v for %s", got, tc.expected, tc.name)
			}
		})
	}
}
