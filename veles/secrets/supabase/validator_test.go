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

package supabase_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/supabase"
)

const (
	validatorTestPAT        = "sbp_1234567890abcdef1234567890abcdef12345678"
	validatorTestSecretKey  = "sb_secret_abcdefghijklmnopqrstuvwxyz123456"
	validatorTestProjectRef = "lphyfymaepklpuvaecry"
)

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if req.URL.Host == "api.supabase.com" || strings.HasSuffix(req.URL.Host, ".supabase.co") {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockSupabasePATServer creates a mock Supabase Management API server for testing PAT
func mockSupabasePATServer(t *testing.T, expectedToken string, serverResponseCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a GET request to the expected endpoint
		if r.Method != http.MethodGet || r.URL.Path != "/v1/projects" {
			t.Errorf("unexpected request: %s %s, expected: GET /v1/projects", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Authorization header
		authHeader := r.Header.Get("Authorization")
		if len(expectedToken) > 0 && !strings.Contains(authHeader, expectedToken) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Set response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(serverResponseCode)
	}))
}

// mockSupabaseProjectServer creates a mock Supabase project-specific API server for testing secret keys
func mockSupabaseProjectServer(t *testing.T, expectedKey string, serverResponseCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a GET request to the expected endpoint
		if r.Method != http.MethodGet || r.URL.Path != "/rest/v1/" {
			t.Errorf("unexpected request: %s %s, expected: GET /rest/v1/", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check apikey and Authorization headers
		apikeyHeader := r.Header.Get("Apikey")
		authHeader := r.Header.Get("Authorization")
		if len(expectedKey) > 0 && (!strings.Contains(apikeyHeader, expectedKey) || !strings.Contains(authHeader, expectedKey)) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Set response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(serverResponseCode)
	}))
}

func TestSupabasePATValidator(t *testing.T) {
	cases := []struct {
		name               string
		token              string
		serverExpectedKey  string
		serverResponseCode int
		want               veles.ValidationStatus
		expectError        bool
	}{
		{
			name:               "valid_pat",
			token:              validatorTestPAT,
			serverExpectedKey:  validatorTestPAT,
			serverResponseCode: http.StatusOK,
			want:               veles.ValidationValid,
		},
		{
			name:               "invalid_pat_unauthorized",
			token:              "sbp_invalid",
			serverExpectedKey:  validatorTestPAT,
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
			server := mockSupabasePATServer(t, tc.serverExpectedKey, tc.serverResponseCode)
			defer server.Close()

			// Create a client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create a validator with a mock client
			validator := supabase.NewPATValidator()
			validator.HTTPC = client

			// Create a test token
			pat := supabase.PAT{Token: tc.token}

			// Test validation
			got, err := validator.Validate(t.Context(), pat)

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

func TestSupabaseProjectSecretKeyValidator(t *testing.T) {
	cases := []struct {
		name               string
		key                string
		projectRef         string
		serverExpectedKey  string
		serverResponseCode int
		want               veles.ValidationStatus
		expectError        bool
	}{
		{
			name:               "valid_secret_key_with_project_ref",
			key:                validatorTestSecretKey,
			projectRef:         validatorTestProjectRef,
			serverExpectedKey:  validatorTestSecretKey,
			serverResponseCode: http.StatusOK,
			want:               veles.ValidationValid,
		},
		{
			name:               "invalid_secret_key_unauthorized",
			key:                "sb_secret_invalid",
			projectRef:         validatorTestProjectRef,
			serverExpectedKey:  validatorTestSecretKey,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:        "secret_key_without_project_ref",
			key:         validatorTestSecretKey,
			projectRef:  "",
			want:        veles.ValidationFailed,
			expectError: true,
		},
		{
			name:               "server_error",
			key:                validatorTestSecretKey,
			projectRef:         validatorTestProjectRef,
			serverResponseCode: http.StatusInternalServerError,
			want:               veles.ValidationFailed,
			expectError:        true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock server
			server := mockSupabaseProjectServer(t, tc.serverExpectedKey, tc.serverResponseCode)
			defer server.Close()

			// Create a client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create a validator with a mock client
			validator := supabase.NewProjectSecretKeyValidator()
			validator.HTTPC = client

			// Create a test secret key
			secretKey := supabase.ProjectSecretKey{
				Key:        tc.key,
				ProjectRef: tc.projectRef,
			}

			// Test validation
			got, err := validator.Validate(t.Context(), secretKey)

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

func TestSupabasePATValidator_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := supabase.NewPATValidator()
	validator.HTTPC = client

	pat := supabase.PAT{Token: validatorTestPAT}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Test validation with cancelled context
	got, err := validator.Validate(ctx, pat)

	if err == nil {
		t.Errorf("Validate() expected error due to context cancellation, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}

func TestSupabaseServiceRoleJWTValidator(t *testing.T) {
	// Valid service_role JWT with ref="lphyfymaepklpuvaecry"
	// Payload: {"iss":"supabase","ref":"lphyfymaepklpuvaecry","role":"service_role","iat":1769261039,"exp":2084837039}
	validJWTWithRef := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImxwaHlmeW1hZXBrbHB1dmFlY3J5Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2OTI2MTAzOSwiZXhwIjoyMDg0ODM3MDM5fQ.signature"

	cases := []struct {
		name               string
		token              string
		serverExpectedKey  string
		serverResponseCode int
		want               veles.ValidationStatus
		expectError        bool
	}{
		{
			name:               "valid_jwt_with_ref",
			token:              validJWTWithRef,
			serverExpectedKey:  validJWTWithRef,
			serverResponseCode: http.StatusOK,
			want:               veles.ValidationValid,
		},
		{
			name:               "invalid_jwt_unauthorized",
			token:              validJWTWithRef,
			serverExpectedKey:  "different_token",
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "server_error",
			token:              validJWTWithRef,
			serverResponseCode: http.StatusInternalServerError,
			want:               veles.ValidationFailed,
			expectError:        true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock server
			server := mockSupabaseProjectServer(t, tc.serverExpectedKey, tc.serverResponseCode)
			defer server.Close()

			// Create a client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create a validator with a mock client
			validator := supabase.NewServiceRoleJWTValidator()
			validator.HTTPC = client

			// Create a test JWT
			jwt := supabase.ServiceRoleJWT{Token: tc.token}

			// Test validation
			got, err := validator.Validate(t.Context(), jwt)

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
