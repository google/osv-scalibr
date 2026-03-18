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
	validatorTestToken = "glcbt-eyJraWQiOiJBYkNkRWZHaElqS2xNbk9wUXJTdFV2V3h5WjEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eiIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJ2ZXJzaW9uIjoiMS4wLjAiLCJvIjoiMTIzIiwidSI6ImFiY2RlIiwicCI6InByb2plY3QxMjMiLCJnIjoiZ3JvdXA0NTYiLCJqdGkiOiIxMjM0NTY3OC05YWJjLTEyMzQtNTY3OC05YWJjZGVmMTIzNDUiLCJhdWQiOiJnaXRsYWItYXV0aHotdG9rZW4iLCJzdWIiOiJnaWQ6Ly9naXRsYWIvQ2k6OkJ1aWxkLzEyMzQ1Njc4OTAiLCJpc3MiOiJnaXRsYWIuY29tIiwiaWF0IjoxNjAwMDAwMDAwLCJuYmYiOjE2MDAwMDAwMDAsImV4cCI6MTYwMDAwMzYwMH0.dGhpc0lzQUR1bW15U2lnbmF0dXJlRm9yVGVzdGluZ1B1cnBvc2VzT25seUFuZFNob3VsZE5vdEJlVXNlZEluUHJvZHVjdGlvbkVudmlyb25tZW50c1RoaXNJc0p1c3RBblRleGFtcGxlVG9rZW5Gb3JUZXN0aW5nVGhlRGV0ZWN0b3JGdW5jdGlvbmFsaXR5QW5kU2hvdWxkTm90QmVDb25zaWRlcmVkQVJlYWxWYWxpZFRva2Vu"
)

// mockJobServer creates a mock GitLab /api/v4/job endpoint for testing.
func mockJobServer(t *testing.T, expectedToken string, statusCode int, body any) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Expect a GET to /api/v4/job
		if r.Method != http.MethodGet || r.URL.Path != "/api/v4/job" {
			t.Errorf("unexpected request: %s %s, expected: GET /api/v4/job", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Job-Token header contains the expected token
		jobTokenHeader := r.Header.Get("Job-Token")
		if expectedToken != "" && jobTokenHeader != expectedToken {
			t.Errorf("expected Job-Token header to be %s, got: %s", expectedToken, jobTokenHeader)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestCIJobTokenValidator(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		body       any
		want       veles.ValidationStatus
		wantErr    error
	}{
		{
			name:       "valid_token",
			statusCode: http.StatusOK,
			body: map[string]any{
				"id":     1234567890,
				"status": "running",
				"user": map[string]any{
					"id":       9876543,
					"username": "example-user",
				},
				"pipeline": map[string]any{
					"id":         9876543210,
					"project_id": 12345678,
				},
			},
			want: veles.ValidationValid,
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
			want:       veles.ValidationFailed,
			wantErr:    cmpopts.AnyError,
		},
		{
			name:       "forbidden_error",
			statusCode: http.StatusForbidden,
			body:       nil,
			want:       veles.ValidationFailed,
			wantErr:    cmpopts.AnyError,
		},
		{
			name:       "not_found_error",
			statusCode: http.StatusNotFound,
			body:       nil,
			want:       veles.ValidationFailed,
			wantErr:    cmpopts.AnyError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server
			server := mockJobServer(t, validatorTestToken, tc.statusCode, tc.body)
			defer server.Close()

			// Create validator with mock client
			validator := gitlab.NewCIJobTokenValidator()
			validator.HTTPC = server.Client()

			// Create test token with custom hostname pointing to test server
			// Use the full server URL which includes http://
			token := gitlab.CIJobToken{
				Token:    validatorTestToken,
				Hostname: server.URL,
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

func TestCIJobTokenValidator_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(nil)
	t.Cleanup(func() {
		server.Close()
	})

	validator := gitlab.NewCIJobTokenValidator()
	validator.HTTPC = server.Client()

	token := gitlab.CIJobToken{
		Token:    validatorTestToken,
		Hostname: server.URL, // Remove "http://" prefix
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

func TestCIJobTokenValidator_InvalidRequest(t *testing.T) {
	// For CI Job Token validator, an "invalid" token is communicated via 401 status.
	server := mockJobServer(t, "", http.StatusUnauthorized, map[string]any{
		"message": "401 Unauthorized",
	})
	defer server.Close()

	validator := gitlab.NewCIJobTokenValidator()
	validator.HTTPC = server.Client()

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
			token:    "invalid-job-token-format",
			expected: veles.ValidationInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k := gitlab.CIJobToken{
				Token:    tc.token,
				Hostname: server.URL, // Remove "http://" prefix
			}

			got, err := validator.Validate(t.Context(), k)

			if err != nil {
				t.Errorf("Validate() unexpected error for %s: %v", tc.name, err)
			}
			if got != tc.expected {
				t.Errorf("Validate() = %v, want %v for %s", got, tc.expected, tc.name)
			}
		})
	}
}

func TestCIJobTokenValidator_DefaultHostname(t *testing.T) {
	// Test that when hostname is empty, it defaults to gitlab.com
	validator := gitlab.NewCIJobTokenValidator()

	token := gitlab.CIJobToken{
		Token:    validatorTestToken,
		Hostname: "", // Empty hostname should default to gitlab.com
	}

	// This will attempt to connect to gitlab.com which will fail,
	// but we're testing that the endpoint construction works correctly
	got, err := validator.Validate(t.Context(), token)

	// We expect either ValidationFailed or ValidationInvalid depending on network
	if got != veles.ValidationFailed && got != veles.ValidationInvalid {
		t.Errorf("Validate() = %v, want ValidationFailed or ValidationInvalid", got)
	}

	// We expect an error since we can't actually connect to gitlab.com in tests
	if err == nil && got == veles.ValidationFailed {
		t.Error("Validate() expected error for failed connection, got nil")
	}
}

func TestCIJobTokenValidator_SelfHostedInstance(t *testing.T) {
	// Test validation against a self-hosted GitLab instance
	server := mockJobServer(t, validatorTestToken, http.StatusOK, map[string]any{
		"id":     9999999,
		"status": "success",
		"user": map[string]any{
			"id":       1111111,
			"username": "self-hosted-user",
		},
		"pipeline": map[string]any{
			"id":         2222222,
			"project_id": 3333333,
		},
	})
	defer server.Close()

	validator := gitlab.NewCIJobTokenValidator()
	validator.HTTPC = server.Client()

	// Test with custom hostname (self-hosted instance)
	token := gitlab.CIJobToken{
		Token:    validatorTestToken,
		Hostname: server.URL, // Remove "http://" prefix
	}

	got, err := validator.Validate(t.Context(), token)

	if err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
	if got != veles.ValidationValid {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationValid)
	}
}
