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

package pypiapitoken_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/pypiapitoken"
)

const validatorTestKey = `pypi-AgEIc433aS5vcmcffDgyZDA0MzFkLWMzZjEtNDlhNy1iOWQwLfflMjE5NmNkMjhjNQACKlszLCI22UBiYzQ2Yi05YjNhhTQ5NmItYWIxMHYhMGI3MmEyOWI5MzYiXQAABiCJBI80LFFz0JvS6UIj2LzgV9N-BQnBAD2123Dyu9xs33`

// mockPyPIServer creates a mock PyPI API server for testing
func mockPyPIServer(t *testing.T, expectedKey string, serverResponseCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a GET request to the expected endpoint
		if r.Method != http.MethodPost || r.URL.Path != "/legacy/" {
			t.Errorf("unexpected request: %s %s, expected: POST /legacy/", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Authorization header
		authHeader := r.Header.Get("Authorization")
		if !strings.Contains(authHeader, expectedKey) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// Set response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(serverResponseCode)
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name               string
		key                string
		serverExpectedKey  string
		serverResponseCode int
		want               veles.ValidationStatus
		expectError        bool
	}{
		{
			name:               "valid_key",
			key:                validatorTestKey,
			serverExpectedKey:  validatorTestKey,
			serverResponseCode: http.StatusBadRequest,
			want:               veles.ValidationValid,
		},
		{
			name:               "invalid_key_unauthorized",
			key:                "random_string",
			serverExpectedKey:  validatorTestKey,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "server_error",
			serverResponseCode: http.StatusInternalServerError,
			want:               veles.ValidationFailed,
			expectError:        true,
		},
		{
			name:               "bad_gateway",
			serverResponseCode: http.StatusBadGateway,
			want:               veles.ValidationFailed,
			expectError:        true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock server
			server := mockPyPIServer(t, tc.serverExpectedKey, tc.serverResponseCode)
			defer server.Close()

			validator := pypiapitoken.NewValidator()
			validator.HTTPC = server.Client()
			validator.Endpoint = server.URL + "/legacy/"

			// Create a test key
			key := pypiapitoken.PyPIAPIToken{Token: tc.key}

			// Test validation
			got, err := validator.Validate(context.Background(), key)

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

	validator := pypiapitoken.NewValidator()
	validator.HTTPC = server.Client()
	validator.Endpoint = server.URL + "/legacy/"

	key := pypiapitoken.PyPIAPIToken{Token: validatorTestKey}

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

func TestValidator_InvalidRequest(t *testing.T) {
	// Create a mock server that returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	validator := pypiapitoken.NewValidator()
	validator.HTTPC = server.Client()
	validator.Endpoint = server.URL + "/legacy/"

	testCases := []struct {
		name        string
		key         string
		expected    veles.ValidationStatus
		expectError bool
	}{
		{
			name:        "empty_key",
			key:         "",
			expected:    veles.ValidationFailed,
			expectError: true,
		},
		{
			name:        "invalid_key_format",
			key:         "invalid-key-format",
			expected:    veles.ValidationFailed,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key := pypiapitoken.PyPIAPIToken{Token: tc.key}

			got, err := validator.Validate(context.Background(), key)

			if tc.expectError {
				if err == nil {
					t.Errorf("Validate() expected error for %s, got nil", tc.name)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error for %s: %v", tc.name, err)
				}
			}
			if got != tc.expected {
				t.Errorf("Validate() = %v, want %v for %s", got, tc.expected, tc.name)
			}
		})
	}
}
