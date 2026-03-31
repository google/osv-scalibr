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

package databrickspat_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/databrickspat"
)

const (
	validatorTestToken = "dapi1234567890abcdef1234567890abcdef"
)

// mockDatabricksServer creates a mock Databricks API server for testing.
func mockDatabricksServer(t *testing.T, expectedToken string, statusCode int) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a GET request to the token list endpoint.
		if r.Method != http.MethodGet || r.URL.Path != databrickspat.TokenListEndpoint {
			t.Errorf("unexpected request: %s %s, expected: GET %s",
				r.Method, r.URL.Path, databrickspat.TokenListEndpoint)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Bearer authentication.
		auth := r.Header.Get("Authorization")
		expectedAuth := "Bearer " + expectedToken
		if auth != expectedAuth {
			t.Errorf("expected Authorization: %s, got: %s", expectedAuth, auth)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
	}))

	return server
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		want       veles.ValidationStatus
		wantErr    error
	}{
		{
			name:       "valid_token_with_permissions",
			statusCode: http.StatusOK,
			want:       veles.ValidationValid,
		},
		{
			name:       "valid_token_insufficient_scope",
			statusCode: http.StatusForbidden,
			want:       veles.ValidationValid,
		},
		{
			name:       "invalid_token",
			statusCode: http.StatusUnauthorized,
			want:       veles.ValidationInvalid,
		},
		{
			name:       "server_error",
			statusCode: http.StatusInternalServerError,
			want:       veles.ValidationFailed,
			wantErr:    cmpopts.AnyError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := mockDatabricksServer(t, validatorTestToken, tc.statusCode)
			defer server.Close()

			validator := databrickspat.NewValidator()
			validator.HTTPC = server.Client()
			// Override endpoint to point to mock server.
			validator.EndpointFunc = func(_ databrickspat.PATCredentials) (string, error) {
				return server.URL + databrickspat.TokenListEndpoint, nil
			}

			creds := databrickspat.PATCredentials{
				Token: validatorTestToken,
				URL:   "test.cloud.databricks.com",
			}

			got, err := validator.Validate(t.Context(), creds)

			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
			}

			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidator_EmptyCredentials(t *testing.T) {
	validator := databrickspat.NewValidator()

	cases := []struct {
		name  string
		creds databrickspat.PATCredentials
	}{
		{
			name:  "empty_token",
			creds: databrickspat.PATCredentials{Token: "", URL: "test.cloud.databricks.com"},
		},
		{
			name:  "empty_url",
			creds: databrickspat.PATCredentials{Token: validatorTestToken, URL: ""},
		},
		{
			name:  "both_empty",
			creds: databrickspat.PATCredentials{Token: "", URL: ""},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validator.Validate(t.Context(), tc.creds)
			if err == nil {
				t.Error("Validate() expected error for empty credentials, got nil")
			}
			if got != veles.ValidationFailed {
				t.Errorf("Validate() = %v, want ValidationFailed", got)
			}
		})
	}
}
