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

package cursorapikey_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/cursorapikey"
)

const (
	validatorTestKey = "key_abcdef0123456789abcdef0123456789" +
		"abcdef0123456789abcdef0123456789"
)

// mockCursorServer creates a mock Cursor API server for testing.
func mockCursorServer(t *testing.T, expectedKey string, statusCode int) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request) {
		meEndpoint := cursorapikey.MeEndpoint
		// Check if it's a GET request to the me endpoint
		if r.Method != http.MethodGet || r.URL.Path != meEndpoint {
			t.Errorf("unexpected request: %s %s, expected: GET %s",
				r.Method, r.URL.Path, meEndpoint)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Basic Authentication (username should be the key, password blank)
		username, password, ok := r.BasicAuth()
		if !ok {
			t.Error("expected Basic Auth header, got none")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if username != expectedKey {
			t.Errorf("expected username (key): %s, got: %s",
				expectedKey, username)
		}

		if password != "" {
			t.Errorf("expected blank password, got: %s", password)
		}

		// Set response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
	}))

	return server
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
			name:       "invalid_key_forbidden",
			statusCode: http.StatusForbidden,
			want:       veles.ValidationInvalid,
		},
		{
			name:       "rate_limited_but_likely_valid",
			statusCode: http.StatusTooManyRequests,
			want:       veles.ValidationValid,
		},
		{
			name:        "server_error",
			statusCode:  http.StatusInternalServerError,
			want:        veles.ValidationFailed,
			expectError: true,
		},
		{
			name:        "bad_request",
			statusCode:  http.StatusBadRequest,
			want:        veles.ValidationFailed,
			expectError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server
			server := mockCursorServer(t, validatorTestKey,
				tc.statusCode)
			defer server.Close()

			// Create validator with mock client and server URL
			validator := cursorapikey.NewValidator()
			validator.HTTPC = server.Client()
			validator.Endpoint = server.URL + cursorapikey.MeEndpoint

			// Create test key
			key := cursorapikey.APIKey{Key: validatorTestKey}

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
