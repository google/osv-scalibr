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

package slacktoken_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/slacktoken"
)

const appLevelTestToken = "xapp-1-A09GDGLM2BE-9538001315143-31fd9c18d0c0c3e9638a7634d01d1ab001d3453ad209e168d5d49b589f0421af"
const appConfigTestAccessToken = "xoxe.xoxp-1-Mi0yLTk1NTI2NjcxMzI3ODYtOTU1MjY2NzEzMzI1MC05NTUyODA2ODE4OTk0LTk1NTI4MDY4MzYxOTQtNWI4NzRmYjU0MTdhZGM3MjYyZmQ5MzNjNGQwMWJhZjhmY2VhMzIyMmQ4NGY4MDZlNjkyYjM5NTMwMjFiZTgwNA"
const appConfigTestRefreshToken = "xoxe-1-My0xLTk1NTI2NjcxMzI3ODYtOTU1MjgwNjgxODk5NC05NTUyODA2ODcxNTU0LTk3Y2UxYWRlYWRlZjhhOWY5ZDRlZTVlOTI4MTRjNWZmYWZlZDU4MTU2OGZhNTIyNmVlYzY5MDE1ZmZmY2FkNTY"

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if req.URL.Host == "slack.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockSlackServer creates a mock Slack API server for testing
func mockSlackServer(t *testing.T, expectedKey string, responseBody string, expectedEndpoint string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a POST request to the expected endpoint
		if r.Method != http.MethodPost {
			t.Errorf("unexpected request method: got %s, expected POST", r.Method)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != expectedEndpoint {
			t.Errorf("unexpected request path: got %s, expected %s", r.URL.Path, expectedEndpoint)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Authorization header for auth.test endpoint
		if expectedEndpoint == "/api/auth.test" {
			authHeader := r.Header.Get("Authorization")
			if !strings.Contains(authHeader, expectedKey) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
				return
			}
		}

		// Check form data for tooling.tokens.rotate endpoint
		if expectedEndpoint == "/api/tooling.tokens.rotate" {
			if err := r.ParseForm(); err != nil {
				t.Errorf("failed to parse form: %v", err)
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			refreshToken := r.Form.Get("refresh_token")
			if refreshToken != expectedKey {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"ok":false,"error":"invalid_refresh_token"}`))
				return
			}
		}

		// Set response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(responseBody))
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name              string
		key               slacktoken.SlackToken
		serverExpectedKey string
		responseBody      string
		expectedEndpoint  string
		want              veles.ValidationStatus
		expectError       bool
	}{
		{
			name:              "valid_app_level_token",
			key:               slacktoken.SlackToken{Token: appLevelTestToken, IsAppLevelToken: true},
			serverExpectedKey: appLevelTestToken,
			responseBody:      `{"ok":true}`,
			expectedEndpoint:  "/api/auth.test",
			want:              veles.ValidationValid,
		},
		{
			name:              "invalid_app_level_token",
			key:               slacktoken.SlackToken{Token: "random_string", IsAppLevelToken: true},
			serverExpectedKey: appLevelTestToken,
			responseBody:      `{"ok":false,"error":"invalid_auth"}`,
			expectedEndpoint:  "/api/auth.test",
			want:              veles.ValidationInvalid,
		},
		{
			name:              "server_error_app_level",
			key:               slacktoken.SlackToken{Token: appLevelTestToken, IsAppLevelToken: true},
			serverExpectedKey: appLevelTestToken,
			responseBody:      `{"ok":false,"error":"server_error"}`,
			expectedEndpoint:  "/api/auth.test",
			want:              veles.ValidationFailed,
		},
		{
			name:              "valid_access_token",
			key:               slacktoken.SlackToken{Token: appConfigTestAccessToken, IsAppConfigAccessToken: true},
			serverExpectedKey: appConfigTestAccessToken,
			responseBody:      `{"ok":true}`,
			expectedEndpoint:  "/api/auth.test",
			want:              veles.ValidationValid,
		},
		{
			name:              "invalid_access_token",
			key:               slacktoken.SlackToken{Token: "invalid_access_token", IsAppConfigAccessToken: true},
			serverExpectedKey: appConfigTestAccessToken,
			responseBody:      `{"ok":false,"error":"invalid_auth"}`,
			expectedEndpoint:  "/api/auth.test",
			want:              veles.ValidationInvalid,
		},
		{
			name:              "valid_refresh_token",
			key:               slacktoken.SlackToken{Token: appConfigTestRefreshToken, IsAppConfigRefreshToken: true},
			serverExpectedKey: appConfigTestRefreshToken,
			responseBody:      `{"ok":true}`,
			expectedEndpoint:  "/api/tooling.tokens.rotate",
			want:              veles.ValidationValid,
		},
		{
			name:              "invalid_refresh_token",
			key:               slacktoken.SlackToken{Token: "invalid_refresh_token", IsAppConfigRefreshToken: true},
			serverExpectedKey: appConfigTestRefreshToken,
			responseBody:      `{"ok":false,"error":"invalid_refresh_token"}`,
			expectedEndpoint:  "/api/tooling.tokens.rotate",
			want:              veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock server
			server := mockSlackServer(t, tc.serverExpectedKey, tc.responseBody, tc.expectedEndpoint)
			defer server.Close()

			// Create a client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create a validator with a mock client
			validator := slacktoken.NewValidator(
				slacktoken.WithClient(client),
			)

			// Test validation
			got, err := validator.Validate(context.Background(), tc.key)

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
	// Create a server that delays response significantly
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sleep longer than the context timeout to trigger cancellation
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true"}`))
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := slacktoken.NewValidator(
		slacktoken.WithClient(client),
	)

	key := slacktoken.SlackToken{Token: appLevelTestToken, IsAppLevelToken: true}

	// Create context with a very short timeout
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

func TestValidator_InvalidRequest(t *testing.T) {
	// Create a mock server that returns invalid auth response
	server := mockSlackServer(t, "any-key", `{"ok":false,"error":"invalid_auth"}`, "/api/auth.test")
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := slacktoken.NewValidator(
		slacktoken.WithClient(client),
	)

	testCases := []struct {
		name     string
		key      slacktoken.SlackToken
		expected veles.ValidationStatus
	}{
		{
			name:     "empty_key",
			key:      slacktoken.SlackToken{Token: "", IsAppLevelToken: true},
			expected: veles.ValidationInvalid,
		},
		{
			name:     "invalid_key_format",
			key:      slacktoken.SlackToken{Token: "invalid-key-format", IsAppLevelToken: true},
			expected: veles.ValidationInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validator.Validate(context.Background(), tc.key)

			if err != nil {
				t.Errorf("Validate() unexpected error for %s: %v", tc.name, err)
			}
			if got != tc.expected {
				t.Errorf("Validate() = %v, want %v for %s", got, tc.expected, tc.name)
			}
		})
	}
}
