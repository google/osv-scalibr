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

package discordbottoken_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/discordbottoken"
)

const (
	validatorTestToken = "MTIzNDU2Nzg5MDEyMzQ1Njc4.G1ab2c.abcdefghijklmnopqrstuvwxyzabc"
)

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL for Discord API hosts.
	if req.URL.Host == "discord.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockDiscordAPIServer creates a mock Discord /users/@me endpoint for testing
// validators.
func mockDiscordAPIServer(t *testing.T, expectedToken string, statusCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Expect a GET to /users/@me
		if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/users/@me") {
			t.Errorf("unexpected request: %s %s, expected: GET /users/@me", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Authorization header
		auth := r.Header.Get("Authorization")
		expectedAuth := "Bot " + expectedToken
		if auth != expectedAuth {
			t.Errorf("expected Authorization header %q, got: %q", expectedAuth, auth)
		}

		w.WriteHeader(statusCode)
	}))
}

func TestValidator(t *testing.T) {
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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server
			server := mockDiscordAPIServer(t, validatorTestToken, tc.statusCode)
			defer server.Close()

			// Create client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create validator with mock client
			validator := discordbottoken.NewValidator()
			validator.HTTPC = client

			// Create test key
			key := discordbottoken.DiscordBotToken{Token: validatorTestToken}

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
	}))
	defer server.Close()

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := discordbottoken.NewValidator()
	validator.HTTPC = client

	key := discordbottoken.DiscordBotToken{Token: validatorTestToken}

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

func TestValidator_EmptyToken(t *testing.T) {
	validator := discordbottoken.NewValidator()

	key := discordbottoken.DiscordBotToken{Token: ""}

	got, err := validator.Validate(t.Context(), key)

	if err == nil {
		t.Errorf("Validate() expected error for empty token, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}
