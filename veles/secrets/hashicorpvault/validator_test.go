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

package hashicorpvault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/osv-scalibr/veles"
)

func TestTokenValidator_Validate(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		expectedStatus veles.ValidationStatus
		expectError    bool
	}{
		{
			name:           "valid token",
			statusCode:     http.StatusOK,
			expectedStatus: veles.ValidationValid,
			expectError:    false,
		},
		{
			name:           "invalid token - unauthorized",
			statusCode:     http.StatusUnauthorized,
			expectedStatus: veles.ValidationInvalid,
			expectError:    false,
		},
		{
			name:           "invalid token - forbidden",
			statusCode:     http.StatusForbidden,
			expectedStatus: veles.ValidationInvalid,
			expectError:    false,
		},
		{
			name:           "server error",
			statusCode:     http.StatusInternalServerError,
			expectedStatus: veles.ValidationFailed,
			expectError:    true,
		},
		{
			name:           "bad gateway",
			statusCode:     http.StatusBadGateway,
			expectedStatus: veles.ValidationFailed,
			expectError:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify the correct endpoint and headers
				if r.URL.Path != "/v1/auth/token/lookup-self" {
					t.Errorf("Expected path /v1/auth/token/lookup-self, got %s", r.URL.Path)
				}
				if r.Method != http.MethodGet {
					t.Errorf("Expected GET method, got %s", r.Method)
				}
				if token := r.Header.Get("X-Vault-Token"); token != "hvs.test-token" {
					t.Errorf("Expected X-Vault-Token header with test token, got %s", token)
				}

				w.WriteHeader(test.statusCode)
			}))
			defer server.Close()

			validator := NewTokenValidator(
				WithClient(server.Client()),
				WithVaultURL(server.URL),
			)

			token := Token{Token: "hvs.test-token"}
			status, err := validator.Validate(t.Context(), token)

			if test.expectError && err == nil {
				t.Fatal("Expected error, got nil")
			}
			if !test.expectError && err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if status != test.expectedStatus {
				t.Errorf("Expected status %v, got %v", test.expectedStatus, status)
			}
		})
	}
}

func TestAppRoleValidator_Validate(t *testing.T) {
	tests := []struct {
		name           string
		credentials    AppRoleCredentials
		statusCode     int
		expectedStatus veles.ValidationStatus
		expectError    bool
	}{
		{
			name: "valid credentials",
			credentials: AppRoleCredentials{
				RoleID:   "12345678-1234-1234-1234-123456789012",
				SecretID: "87654321-4321-4321-4321-210987654321",
			},
			statusCode:     http.StatusOK,
			expectedStatus: veles.ValidationValid,
			expectError:    false,
		},
		{
			name: "invalid credentials - unauthorized",
			credentials: AppRoleCredentials{
				RoleID:   "12345678-1234-1234-1234-123456789012",
				SecretID: "invalid-secret",
			},
			statusCode:     http.StatusUnauthorized,
			expectedStatus: veles.ValidationInvalid,
			expectError:    false,
		},
		{
			name: "invalid credentials - bad request",
			credentials: AppRoleCredentials{
				RoleID:   "invalid-role-id",
				SecretID: "87654321-4321-4321-4321-210987654321",
			},
			statusCode:     http.StatusBadRequest,
			expectedStatus: veles.ValidationInvalid,
			expectError:    false,
		},
		{
			name: "server error",
			credentials: AppRoleCredentials{
				RoleID:   "12345678-1234-1234-1234-123456789012",
				SecretID: "87654321-4321-4321-4321-210987654321",
			},
			statusCode:     http.StatusInternalServerError,
			expectedStatus: veles.ValidationFailed,
			expectError:    true,
		},
		{
			name: "missing role_id",
			credentials: AppRoleCredentials{
				RoleID:   "",
				SecretID: "87654321-4321-4321-4321-210987654321",
			},
			statusCode:     0, // Won't make HTTP request
			expectedStatus: veles.ValidationFailed,
			expectError:    true,
		},
		{
			name: "missing secret_id",
			credentials: AppRoleCredentials{
				RoleID:   "12345678-1234-1234-1234-123456789012",
				SecretID: "",
			},
			statusCode:     0, // Won't make HTTP request
			expectedStatus: veles.ValidationFailed,
			expectError:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify the correct endpoint and headers
				if r.URL.Path != "/v1/auth/approle/login" {
					t.Errorf("Expected path /v1/auth/approle/login, got %s", r.URL.Path)
				}
				if r.Method != http.MethodPost {
					t.Errorf("Expected POST method, got %s", r.Method)
				}
				if contentType := r.Header.Get("Content-Type"); contentType != "application/json" {
					t.Errorf("Expected Content-Type application/json, got %s", contentType)
				}

				w.WriteHeader(test.statusCode)
			}))
			defer server.Close()

			validator := NewAppRoleValidator(
				WithClient(server.Client()),
				WithVaultURL(server.URL),
			)

			status, err := validator.Validate(t.Context(), test.credentials)

			if test.expectError && err == nil {
				t.Fatal("Expected error, got nil")
			}
			if !test.expectError && err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if status != test.expectedStatus {
				t.Errorf("Expected status %v, got %v", test.expectedStatus, status)
			}
		})
	}
}

func TestValidator_InvalidVaultURL(t *testing.T) {
	validator := NewTokenValidator(WithVaultURL("://invalid-url"))
	token := Token{Token: "hvs.test-token"}
	status, err := validator.Validate(t.Context(), token)

	if err == nil {
		t.Fatal("Expected error for invalid URL, got nil")
	}
	if status != veles.ValidationFailed {
		t.Errorf("Expected ValidationFailed status, got %v", status)
	}
}

func TestValidator_NetworkError(t *testing.T) {
	// Use a URL that will cause a network error
	validator := NewTokenValidator(WithVaultURL("http://localhost:1"))
	token := Token{Token: "hvs.test-token"}
	status, err := validator.Validate(t.Context(), token)

	if err == nil {
		t.Fatal("Expected network error, got nil")
	}
	if status != veles.ValidationFailed {
		t.Errorf("Expected ValidationFailed status, got %v", status)
	}
}

func TestValidator_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This handler will never respond, allowing us to test context cancellation
		select {}
	}))
	defer server.Close()

	validator := NewTokenValidator(
		WithClient(server.Client()),
		WithVaultURL(server.URL),
	)

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Cancel immediately

	token := Token{Token: "hvs.test-token"}
	status, err := validator.Validate(ctx, token)

	if err == nil {
		t.Fatal("Expected context cancellation error, got nil")
	}
	if status != veles.ValidationFailed {
		t.Errorf("Expected ValidationFailed status, got %v", status)
	}
}
