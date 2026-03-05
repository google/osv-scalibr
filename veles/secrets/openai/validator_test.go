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

package openai_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/openai"
)

const (
	projectValidatorTestKey = "sk-proj-12345678901234567890T3BlbkFJ" +
		"12345678901234567890123456"
)

// mockOpenAIServer creates a mock OpenAI API server for testing project keys
func mockOpenAIServer(t *testing.T, expectedKey string, statusCode int) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request) {
		modelsEndpoint := openai.ModelsEndpoint
		// Check if it's a GET request to the models endpoint
		if r.Method != http.MethodGet || r.URL.Path != modelsEndpoint {
			t.Errorf("unexpected request: %s %s, expected: GET %s",
				r.Method, r.URL.Path, modelsEndpoint)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Authorization header (Bearer token format)
		expectedAuth := "Bearer " + expectedKey
		if r.Header.Get("Authorization") != expectedAuth {
			t.Errorf("expected Authorization: %s, got: %s",
				expectedAuth, r.Header.Get("Authorization"))
		}

		// Set response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
	}))

	return server
}

func TestProjectValidator(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		want       veles.ValidationStatus
		wantErr    error
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
			name:       "forbidden_but_likely_valid",
			statusCode: http.StatusForbidden,
			want:       veles.ValidationFailed,
			wantErr:    cmpopts.AnyError,
		},
		{
			name:       "rate_limited_but_likely_valid",
			statusCode: http.StatusTooManyRequests,
			want:       veles.ValidationValid,
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
			// Create mock server
			server := mockOpenAIServer(t, projectValidatorTestKey,
				tc.statusCode)
			defer server.Close()

			// Create validator with mock client and server URL
			validator := openai.NewProjectValidator()
			validator.HTTPC = server.Client()
			validator.Endpoint = server.URL + openai.ModelsEndpoint

			key := openai.APIKey{Key: projectValidatorTestKey}

			got, err := validator.Validate(t.Context(), key)

			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
			}

			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}
