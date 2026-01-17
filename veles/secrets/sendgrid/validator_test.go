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

package sendgrid_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/sendgrid"
)

// mockSendGridServer creates a mock SendGrid API server for testing.
func mockSendGridServer(t *testing.T, expectedKey string, statusCode int, expectedEndpoint string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a GET request to the expected endpoint
		if r.Method != http.MethodGet {
			t.Errorf("unexpected request method: got %s, expected GET", r.Method)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != expectedEndpoint {
			t.Errorf("unexpected request path: got %s, expected %s", r.URL.Path, expectedEndpoint)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Authorization header
		authHeader := r.Header.Get("Authorization")
		expectedAuth := "Bearer " + expectedKey
		if authHeader != expectedAuth {
			// Return 401 for invalid auth
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"errors":[{"message":"authorization required"}]}`))
			return
		}

		// Set response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if statusCode == http.StatusOK {
			_, _ = w.Write([]byte(`{"type":"free","reputation":99.7}`))
		}
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name              string
		key               sendgrid.APIKey
		serverExpectedKey string
		statusCode        int
		expectedEndpoint  string
		want              veles.ValidationStatus
		expectError       bool
	}{
		{
			name:              "valid_key_returns_200",
			key:               sendgrid.APIKey{Key: testSendGridAPIKey},
			serverExpectedKey: testSendGridAPIKey,
			statusCode:        http.StatusOK,
			expectedEndpoint:  "/v3/user/account",
			want:              veles.ValidationValid,
		},
		{
			name:              "valid_key_without_permission_returns_403",
			key:               sendgrid.APIKey{Key: testSendGridAPIKey},
			serverExpectedKey: testSendGridAPIKey,
			statusCode:        http.StatusForbidden,
			expectedEndpoint:  "/v3/user/account",
			want:              veles.ValidationValid,
		},
		{
			name:              "invalid_key_returns_401",
			key:               sendgrid.APIKey{Key: "invalid_key"},
			serverExpectedKey: testSendGridAPIKey,
			statusCode:        http.StatusUnauthorized,
			expectedEndpoint:  "/v3/user/account",
			want:              veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock server
			server := mockSendGridServer(t, tc.serverExpectedKey, tc.statusCode, tc.expectedEndpoint)
			defer server.Close()

			validator := sendgrid.NewValidator()
			validator.HTTPC = server.Client()
			validator.Endpoint = server.URL + "/v3/user/account"

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
		_, _ = w.Write([]byte(`{"type":"free","reputation":99.7}`))
	}))
	defer server.Close()

	validator := sendgrid.NewValidator()
	validator.HTTPC = server.Client()
	validator.Endpoint = server.URL + "/v3/user/account"
	key := sendgrid.APIKey{Key: testSendGridAPIKey}

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
}

func TestValidator_ServerErrors(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		want       veles.ValidationStatus
	}{
		{
			name:       "rate_limited_429",
			statusCode: http.StatusTooManyRequests,
			want:       veles.ValidationFailed,
		},
		{
			name:       "server_error_500",
			statusCode: http.StatusInternalServerError,
			want:       veles.ValidationFailed,
		},
		{
			name:       "service_unavailable_503",
			statusCode: http.StatusServiceUnavailable,
			want:       veles.ValidationFailed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
			}))
			defer server.Close()

			validator := sendgrid.NewValidator()
			validator.HTTPC = server.Client()
			validator.Endpoint = server.URL + "/v3/user/account"
			key := sendgrid.APIKey{Key: testSendGridAPIKey}

			got, _ := validator.Validate(t.Context(), key)

			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidator_AuthorizationHeader(t *testing.T) {
	var capturedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	validator := sendgrid.NewValidator()
	validator.HTTPC = server.Client()
	validator.Endpoint = server.URL + "/v3/user/account"

	key := sendgrid.APIKey{Key: testSendGridAPIKey}
	validator.Validate(t.Context(), key)

	expectedAuth := "Bearer " + testSendGridAPIKey
	if capturedAuth != expectedAuth {
		t.Errorf("Authorization header = %q, want %q", capturedAuth, expectedAuth)
	}
}
