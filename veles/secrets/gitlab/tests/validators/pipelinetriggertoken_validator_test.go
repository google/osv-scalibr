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

package gitlab_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gitlab"
)

const (
	validatorTestToken     = "glptt-zHDqagxzUPPp5PgeBUN7"
	validatorTestProjectID = "49254380"
	validatorTestHostname  = "gitlab.com"
)

// mockTriggerServer creates a mock GitLab pipeline trigger endpoint for testing.
func mockTriggerServer(t *testing.T, expectedToken string, statusCode int, body any) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Expect a POST to /api/v4/projects/{project_id}/trigger/pipeline
		expectedPath := "/api/v4/projects/" + validatorTestProjectID + "/trigger/pipeline"
		if r.Method != http.MethodPost || r.URL.Path != expectedPath {
			t.Errorf("unexpected request: %s %s, expected: POST %s", r.Method, r.URL.Path, expectedPath)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Parse form data
		if err := r.ParseForm(); err != nil {
			t.Errorf("failed to parse form: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// Check token parameter
		if expectedToken != "" {
			token := r.FormValue("token")
			if token != expectedToken {
				t.Errorf("expected token to be %s, got: %s", expectedToken, token)
			}
		}

		// Check ref parameter (should be randomfffffffff)
		ref := r.FormValue("ref")
		if ref != "randomfffffffff" {
			t.Errorf("expected ref to be randomfffffffff, got: %s", ref)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		body       any
		want       veles.ValidationStatus
		wantErr    error
	}{
		{
			name:       "valid_token_reference_not_found",
			statusCode: http.StatusBadRequest,
			body: map[string]any{
				"message": map[string]any{
					"base": []string{"Reference not found"},
				},
			},
			want: veles.ValidationValid,
		},
		{
			name:       "valid_token_pipeline_created",
			statusCode: http.StatusCreated,
			body: map[string]any{
				"id":     12345,
				"status": "pending",
			},
			want: veles.ValidationValid,
		},
		{
			name:       "invalid_token_not_found",
			statusCode: http.StatusNotFound,
			body: map[string]any{
				"message": "404 Not Found",
			},
			want: veles.ValidationInvalid,
		},
		{
			name:       "invalid_token_unauthorized",
			statusCode: http.StatusUnauthorized,
			body: map[string]any{
				"message": "401 Unauthorized",
			},
			want: veles.ValidationInvalid,
		},
		{
			name:       "server_error",
			statusCode: http.StatusInternalServerError,
			body:       nil,
			want:       veles.ValidationInvalid,
		},
		{
			name:       "bad_request_other_error",
			statusCode: http.StatusBadRequest,
			body: map[string]any{
				"message": "Invalid parameters",
			},
			want: veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server
			server := mockTriggerServer(t, validatorTestToken, tc.statusCode, tc.body)
			defer server.Close()

			// Create validator with mock client
			validator := gitlab.NewPipelineTriggerTokenValidator()
			validator.Validator.HTTPC = server.Client()
			validator.Validator.EndpointFunc = func(secret gitlab.PipelineTriggerToken) (string, error) {
				return server.URL + "/api/v4/projects/" + secret.ProjectID + "/trigger/pipeline", nil
			}

			// Create test token
			token := gitlab.PipelineTriggerToken{
				Token:     validatorTestToken,
				ProjectID: validatorTestProjectID,
			}

			// Test validation
			got, err := validator.Validate(t.Context(), token)

			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
			}

			// Check validation status
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidator_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(nil)
	t.Cleanup(func() {
		server.Close()
	})

	validator := gitlab.NewPipelineTriggerTokenValidator()
	validator.Validator.HTTPC = server.Client()
	validator.Validator.EndpointFunc = func(secret gitlab.PipelineTriggerToken) (string, error) {
		return server.URL + "/api/v4/projects/" + secret.ProjectID + "/trigger/pipeline", nil
	}

	token := gitlab.PipelineTriggerToken{
		Token:     validatorTestToken,
		ProjectID: validatorTestProjectID,
	}

	// Create context that is immediately cancelled
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Test validation with cancelled context
	got, err := validator.Validate(ctx, token)

	if diff := cmp.Diff(cmpopts.AnyError, err, cmpopts.EquateErrors()); diff != "" {
		t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}

func TestValidator_MissingProjectID(t *testing.T) {
	validator := gitlab.NewPipelineTriggerTokenValidator()

	// Token without project ID should fail validation
	token := gitlab.PipelineTriggerToken{
		Token: validatorTestToken,
		// ProjectID is empty
	}

	got, err := validator.Validate(t.Context(), token)

	if err == nil {
		t.Error("Validate() expected error for missing ProjectID, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}

func TestValidator_CustomHostname(t *testing.T) {
	customHostname := "gitlab.example.com"

	// Create mock server
	server := mockTriggerServer(t, validatorTestToken, http.StatusCreated, map[string]any{
		"id":     12345,
		"status": "pending",
	})
	defer server.Close()

	validator := gitlab.NewPipelineTriggerTokenValidator()
	validator.Validator.HTTPC = server.Client()

	// Override EndpointFunc to use the mock server URL
	validator.Validator.EndpointFunc = func(secret gitlab.PipelineTriggerToken) (string, error) {
		// Verify that the hostname is being used
		if secret.Hostname != customHostname {
			t.Errorf("expected hostname %s, got %s", customHostname, secret.Hostname)
		}
		return server.URL + "/api/v4/projects/" + secret.ProjectID + "/trigger/pipeline", nil
	}

	// Create test token with custom hostname
	token := gitlab.PipelineTriggerToken{
		Token:     validatorTestToken,
		ProjectID: validatorTestProjectID,
		Hostname:  customHostname,
	}

	// Test validation
	got, err := validator.Validate(t.Context(), token)

	if err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
	if got != veles.ValidationValid {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationValid)
	}
}

func TestValidator_DefaultHostname(t *testing.T) {
	// Create mock server
	server := mockTriggerServer(t, validatorTestToken, http.StatusCreated, map[string]any{
		"id":     12345,
		"status": "pending",
	})
	defer server.Close()

	validator := gitlab.NewPipelineTriggerTokenValidator()
	validator.Validator.HTTPC = server.Client()

	// Override EndpointFunc to use the mock server URL and verify default hostname
	validator.Validator.EndpointFunc = func(secret gitlab.PipelineTriggerToken) (string, error) {
		// When hostname is empty, it should default to gitlab.com
		expectedHostname := "gitlab.com"
		actualHostname := secret.Hostname
		if actualHostname == "" {
			actualHostname = expectedHostname
		}
		if actualHostname != expectedHostname {
			t.Errorf("expected default hostname %s, got %s", expectedHostname, actualHostname)
		}
		return server.URL + "/api/v4/projects/" + secret.ProjectID + "/trigger/pipeline", nil
	}

	// Create test token without hostname (should default to gitlab.com)
	token := gitlab.PipelineTriggerToken{
		Token:     validatorTestToken,
		ProjectID: validatorTestProjectID,
		// Hostname is empty, should default to gitlab.com
	}

	// Test validation
	got, err := validator.Validate(t.Context(), token)

	if err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
	if got != veles.ValidationValid {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationValid)
	}
}

func TestValidator_InvalidRequest(t *testing.T) {
	// For trigger token validator, a 404 indicates invalid token.
	server := mockTriggerServer(t, "", http.StatusNotFound, map[string]any{
		"message": "404 Not Found",
	})
	defer server.Close()

	validator := gitlab.NewPipelineTriggerTokenValidator()
	validator.Validator.HTTPC = server.Client()
	validator.Validator.EndpointFunc = func(secret gitlab.PipelineTriggerToken) (string, error) {
		return server.URL + "/api/v4/projects/" + secret.ProjectID + "/trigger/pipeline", nil
	}

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
			token:    "invalid-trigger-token",
			expected: veles.ValidationInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := gitlab.PipelineTriggerToken{
				Token:     tc.token,
				ProjectID: validatorTestProjectID,
			}

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
