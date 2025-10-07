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
				_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
				return
			}
		}
		// Set response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(responseBody))
	}))
}

func TestAppLevelTokenValidator(t *testing.T) {
	cases := []struct {
		name              string
		key               slacktoken.SlackAppLevelToken
		serverExpectedKey string
		responseBody      string
		expectedEndpoint  string
		want              veles.ValidationStatus
		expectError       bool
	}{
		{
			name:              "valid_app_level_token",
			key:               slacktoken.SlackAppLevelToken{Token: testAppLevelToken},
			serverExpectedKey: testAppLevelToken,
			responseBody:      `{"ok":true}`,
			expectedEndpoint:  "/api/auth.test",
			want:              veles.ValidationValid,
		},
		{
			name:              "invalid_app_level_token",
			key:               slacktoken.SlackAppLevelToken{Token: "random_string"},
			serverExpectedKey: testAppLevelToken,
			responseBody:      `{"ok":false,"error":"invalid_auth"}`,
			expectedEndpoint:  "/api/auth.test",
			want:              veles.ValidationInvalid,
		},
		{
			name:              "server_error_app_level",
			key:               slacktoken.SlackAppLevelToken{Token: testAppLevelToken},
			serverExpectedKey: testAppLevelToken,
			responseBody:      `{"ok":false,"error":"server_error"}`,
			expectedEndpoint:  "/api/auth.test",
			want:              veles.ValidationFailed,
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
			validator := slacktoken.NewAppLevelTokenValidator(
				slacktoken.WithClientAppLevelToken(client),
			)

			// Test validation
			got, err := validator.Validate(t.Context(), tc.key)

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

func TestAppConfigAccessTokenValidator(t *testing.T) {
	cases := []struct {
		name              string
		key               slacktoken.SlackAppConfigAccessToken
		serverExpectedKey string
		responseBody      string
		expectedEndpoint  string
		want              veles.ValidationStatus
		expectError       bool
	}{
		{
			name:              "valid_access_token",
			key:               slacktoken.SlackAppConfigAccessToken{Token: testAppConfigAccessToken},
			serverExpectedKey: testAppConfigAccessToken,
			responseBody:      `{"ok":true}`,
			expectedEndpoint:  "/api/auth.test",
			want:              veles.ValidationValid,
		},
		{
			name:              "invalid_access_token",
			key:               slacktoken.SlackAppConfigAccessToken{Token: "invalid_access_token"},
			serverExpectedKey: testAppConfigAccessToken,
			responseBody:      `{"ok":false,"error":"invalid_auth"}`,
			expectedEndpoint:  "/api/auth.test",
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
			validator := slacktoken.NewAppConfigAccessTokenValidator(
				slacktoken.WithClientAppConfigAccessToken(client),
			)

			// Test validation
			got, err := validator.Validate(t.Context(), tc.key)

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

func TestAppConfigRefreshTokenValidator(t *testing.T) {
	cases := []struct {
		name              string
		key               slacktoken.SlackAppConfigRefreshToken
		serverExpectedKey string
		responseBody      string
		expectedEndpoint  string
		want              veles.ValidationStatus
		expectError       bool
	}{
		{
			name:              "valid_refresh_token",
			key:               slacktoken.SlackAppConfigRefreshToken{Token: testAppConfigRefreshToken},
			serverExpectedKey: testAppConfigRefreshToken,
			responseBody:      `{"ok":true}`,
			expectedEndpoint:  "/api/auth.test",
			want:              veles.ValidationValid,
		},
		{
			name:              "invalid_refresh_token",
			key:               slacktoken.SlackAppConfigRefreshToken{Token: "invalid_refresh_token"},
			serverExpectedKey: testAppConfigRefreshToken,
			responseBody:      `{"ok":false,"error":"invalid_auth"}`,
			expectedEndpoint:  "/api/auth.test",
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
			validator := slacktoken.NewAppConfigRefreshTokenValidator(
				slacktoken.WithClientAppConfigRefreshToken(client),
			)

			// Test validation
			got, err := validator.Validate(t.Context(), tc.key)

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
		_, _ = w.Write([]byte(`{"ok":true"}`))
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	// Test with App Level Token validator
	t.Run("app_level_token", func(t *testing.T) {
		validator := slacktoken.NewAppLevelTokenValidator(
			slacktoken.WithClientAppLevelToken(client),
		)

		key := slacktoken.SlackAppLevelToken{Token: testAppLevelToken}

		// Create context with a very short timeout
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		defer cancel()

		// Test validation with cancelled context
		got, err := validator.Validate(ctx, key)

		if err == nil {
			t.Errorf("Validate() expected error due to context cancellation, got nil")
		}
		if got != veles.ValidationFailed {
			t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
		}
	})

	// Test with App Config Access Token validator
	t.Run("app_config_access_token", func(t *testing.T) {
		validator := slacktoken.NewAppConfigAccessTokenValidator(
			slacktoken.WithClientAppConfigAccessToken(client),
		)

		key := slacktoken.SlackAppConfigAccessToken{Token: testAppConfigAccessToken}

		// Create context with a very short timeout
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		defer cancel()

		// Test validation with cancelled context
		got, err := validator.Validate(ctx, key)

		if err == nil {
			t.Errorf("Validate() expected error due to context cancellation, got nil")
		}
		if got != veles.ValidationFailed {
			t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
		}
	})

	// Test with App Config Refresh Token validator
	t.Run("app_config_refresh_token", func(t *testing.T) {
		validator := slacktoken.NewAppConfigRefreshTokenValidator(
			slacktoken.WithClientAppConfigRefreshToken(client),
		)

		key := slacktoken.SlackAppConfigRefreshToken{Token: testAppConfigRefreshToken}

		// Create context with a very short timeout
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		defer cancel()

		// Test validation with cancelled context
		got, err := validator.Validate(ctx, key)

		if err == nil {
			t.Errorf("Validate() expected error due to context cancellation, got nil")
		}
		if got != veles.ValidationFailed {
			t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
		}
	})
}

func TestValidator_InvalidRequest(t *testing.T) {
	// Create a mock server that returns invalid auth response
	server := mockSlackServer(t, "any-key", `{"ok":false,"error":"invalid_auth"}`, "/api/auth.test")
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	// Test with App Level Token validator
	t.Run("app_level_token", func(t *testing.T) {
		validator := slacktoken.NewAppLevelTokenValidator(
			slacktoken.WithClientAppLevelToken(client),
		)

		testCases := []struct {
			name     string
			key      slacktoken.SlackAppLevelToken
			expected veles.ValidationStatus
		}{
			{
				name:     "empty_key",
				key:      slacktoken.SlackAppLevelToken{Token: ""},
				expected: veles.ValidationInvalid,
			},
			{
				name:     "invalid_key_format",
				key:      slacktoken.SlackAppLevelToken{Token: "invalid-key-format"},
				expected: veles.ValidationInvalid,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := validator.Validate(t.Context(), tc.key)

				if err != nil {
					t.Errorf("Validate() unexpected error for %s: %v", tc.name, err)
				}
				if got != tc.expected {
					t.Errorf("Validate() = %v, want %v for %s", got, tc.expected, tc.name)
				}
			})
		}
	})

	// Test with App Config Access Token validator
	t.Run("app_config_access_token", func(t *testing.T) {
		validator := slacktoken.NewAppConfigAccessTokenValidator(
			slacktoken.WithClientAppConfigAccessToken(client),
		)

		testCases := []struct {
			name     string
			key      slacktoken.SlackAppConfigAccessToken
			expected veles.ValidationStatus
		}{
			{
				name:     "empty_key",
				key:      slacktoken.SlackAppConfigAccessToken{Token: ""},
				expected: veles.ValidationInvalid,
			},
			{
				name:     "invalid_key_format",
				key:      slacktoken.SlackAppConfigAccessToken{Token: "invalid-key-format"},
				expected: veles.ValidationInvalid,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := validator.Validate(t.Context(), tc.key)

				if err != nil {
					t.Errorf("Validate() unexpected error for %s: %v", tc.name, err)
				}
				if got != tc.expected {
					t.Errorf("Validate() = %v, want %v for %s", got, tc.expected, tc.name)
				}
			})
		}
	})

	// Test with App Config Refresh Token validator
	t.Run("app_config_refresh_token", func(t *testing.T) {
		validator := slacktoken.NewAppConfigRefreshTokenValidator(
			slacktoken.WithClientAppConfigRefreshToken(client),
		)

		testCases := []struct {
			name     string
			key      slacktoken.SlackAppConfigRefreshToken
			expected veles.ValidationStatus
		}{
			{
				name:     "empty_key",
				key:      slacktoken.SlackAppConfigRefreshToken{Token: ""},
				expected: veles.ValidationInvalid,
			},
			{
				name:     "invalid_key_format",
				key:      slacktoken.SlackAppConfigRefreshToken{Token: "invalid-key-format"},
				expected: veles.ValidationInvalid,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := validator.Validate(t.Context(), tc.key)

				if err != nil {
					t.Errorf("Validate() unexpected error for %s: %v", tc.name, err)
				}
				if got != tc.expected {
					t.Errorf("Validate() = %v, want %v for %s", got, tc.expected, tc.name)
				}
			})
		}
	})
}
