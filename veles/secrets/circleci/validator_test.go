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

package circleci_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/circleci"
)

const (
	validatorTestPAT     = "CCIPAT_GHFzqc7fRZ2GviZQ7hbdeb_9f54ac82eef4bb69a8fece88199a7414f32d8b36"
	validatorTestProject = "CCIPRJ_Nw1xCXXyTW8uvdkHKLNUqK_4ad9cadd8b2b29d02a49ed03720fac5644f66c92"
)

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if req.URL.Host == "circleci.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockCircleCIPATServer creates a mock CircleCI API server for PAT validation
func mockCircleCIPATServer(t *testing.T, expectedToken string, serverResponseCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a GET request to the expected endpoint
		if r.Method != http.MethodGet || r.URL.Path != "/api/v2/me" {
			t.Errorf("unexpected request: %s %s, expected: GET /api/v2/me", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Circle-Token header
		tokenHeader := r.Header.Get("Circle-Token")
		if len(expectedToken) > 0 && tokenHeader != expectedToken {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Set response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(serverResponseCode)
	}))
}

func TestPersonalAccessTokenValidator(t *testing.T) {
	cases := []struct {
		name                string
		token               string
		serverExpectedToken string
		serverResponseCode  int
		want                veles.ValidationStatus
		expectError         bool
	}{
		{
			name:                "valid_token",
			token:               validatorTestPAT,
			serverExpectedToken: validatorTestPAT,
			serverResponseCode:  http.StatusOK,
			want:                veles.ValidationValid,
		},
		{
			name:                "invalid_token_unauthorized",
			token:               "CCIPAT_invalid_token_1234567890_1234567890123456789012345678901234567890",
			serverExpectedToken: validatorTestPAT,
			serverResponseCode:  http.StatusUnauthorized,
			want:                veles.ValidationInvalid,
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
			server := mockCircleCIPATServer(t, tc.serverExpectedToken, tc.serverResponseCode)
			defer server.Close()

			// Create a client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create a validator with a mock client
			validator := circleci.NewPersonalAccessTokenValidator()
			validator.HTTPC = client

			// Create a test token
			token := circleci.PersonalAccessToken{Token: tc.token}

			// Test validation
			got, err := validator.Validate(t.Context(), token)

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

// mockCircleCIProjectServer creates a mock CircleCI API server for Project token validation
func mockCircleCIProjectServer(t *testing.T, expectedToken string, serverResponseCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a GET request to the expected endpoint
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/api/v1.1/project/") {
			t.Errorf("unexpected request: %s %s, expected: GET /api/v1.1/project/*", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Circle-Token header
		tokenHeader := r.Header.Get("Circle-Token")
		if len(expectedToken) > 0 && tokenHeader != expectedToken {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Set response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(serverResponseCode)
		if serverResponseCode == http.StatusNotFound {
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
		}
	}))
}

func TestProjectTokenValidator(t *testing.T) {
	cases := []struct {
		name                string
		token               string
		serverExpectedToken string
		serverResponseCode  int
		want                veles.ValidationStatus
		expectError         bool
	}{
		{
			name:                "valid_token_project_not_found",
			token:               validatorTestProject,
			serverExpectedToken: validatorTestProject,
			serverResponseCode:  http.StatusNotFound,
			want:                veles.ValidationValid,
		},
		{
			name:                "valid_token_project_exists",
			token:               validatorTestProject,
			serverExpectedToken: validatorTestProject,
			serverResponseCode:  http.StatusOK,
			want:                veles.ValidationValid,
		},
		{
			name:                "invalid_token_unauthorized",
			token:               "CCIPRJ_invalid_token_1234567890_1234567890123456789012345678901234567890",
			serverExpectedToken: validatorTestProject,
			serverResponseCode:  http.StatusUnauthorized,
			want:                veles.ValidationInvalid,
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
			server := mockCircleCIProjectServer(t, tc.serverExpectedToken, tc.serverResponseCode)
			defer server.Close()

			// Create a client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create a validator with a mock client
			validator := circleci.NewProjectTokenValidator()
			validator.HTTPC = client

			// Create a test token
			token := circleci.ProjectToken{Token: tc.token}

			// Test validation
			got, err := validator.Validate(t.Context(), token)

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

func TestPersonalAccessTokenValidator_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := circleci.NewPersonalAccessTokenValidator()
	validator.HTTPC = client

	token := circleci.PersonalAccessToken{Token: validatorTestPAT}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Test validation with cancelled context
	got, err := validator.Validate(ctx, token)

	if err == nil {
		t.Errorf("Validate() expected error due to context cancellation, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}

func TestProjectTokenValidator_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := circleci.NewProjectTokenValidator()
	validator.HTTPC = client

	token := circleci.ProjectToken{Token: validatorTestProject}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Test validation with cancelled context
	got, err := validator.Validate(ctx, token)

	if err == nil {
		t.Errorf("Validate() expected error due to context cancellation, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}
