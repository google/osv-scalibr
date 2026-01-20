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

package dockerhubpat_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/dockerhubpat"
)

const validatorTestPat = "dckr_oat_7awgM4jG5SQvxcvmNzhKj8PQjxo"
const validatorTestUsername = "User123"

// mockDockerHubServer creates a mock Docker Hub API server for testing
func mockDockerHubServer(t *testing.T, expectedKey string, expectedUser string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a POST request to the expected endpoint
		if r.Method != http.MethodPost ||
			r.URL.Path != "/v2/auth/token/" ||
			r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected request: %s %s, expected: POST /v2/auth/token/ with content type application/json", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Body
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read request body: %v", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()
		bodyString := string(bodyBytes)
		expectedBody := fmt.Sprintf("{\"identifier\": \"%s\",\"secret\": \"%s\"}", expectedUser, expectedKey)
		if expectedBody != bodyString {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name     string
		Username string
		Pat      string
		want     veles.ValidationStatus
	}{
		{
			name:     "invalid key and username",
			Pat:      "dckr_oat_random",
			Username: "User2",
			want:     veles.ValidationInvalid,
		},
		{
			name:     "valid key and username",
			Pat:      validatorTestPat,
			Username: validatorTestUsername,
			want:     veles.ValidationValid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock server
			server := mockDockerHubServer(t, validatorTestPat, validatorTestUsername)
			defer server.Close()

			// Create a validator with a mock client
			validator := dockerhubpat.NewValidator()
			validator.HTTPC = server.Client()
			validator.Endpoint = server.URL + "/v2/auth/token/"

			// Create a test username and pat
			usernamePat := dockerhubpat.DockerHubPAT{Pat: tc.Pat, Username: tc.Username}

			// Test validation
			got, err := validator.Validate(t.Context(), usernamePat)

			if !cmp.Equal(err, nil, cmpopts.EquateErrors()) {
				t.Fatalf("plugin.Validate(%v) got error: %v\n", usernamePat, err)
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

	validator := dockerhubpat.NewValidator()
	validator.HTTPC = server.Client()
	validator.Endpoint = server.URL + "/v2/auth/token/"

	// Create a test username and pat
	usernamePat := dockerhubpat.DockerHubPAT{Pat: validatorTestPat, Username: validatorTestUsername}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Test validation with cancelled context
	got, err := validator.Validate(ctx, usernamePat)

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

	validator := dockerhubpat.NewValidator()
	validator.HTTPC = server.Client()
	validator.Endpoint = server.URL + "/v2/auth/token/"

	testCases := []struct {
		name     string
		Pat      string
		Username string
		expected veles.ValidationStatus
		wantErr  bool
	}{
		{
			name:     "empty_key",
			Pat:      "",
			Username: validatorTestUsername,
			expected: veles.ValidationInvalid,
		},
		{
			name:     "invalid_key_format",
			Pat:      "invalid-key-format",
			Username: validatorTestUsername,
			expected: veles.ValidationInvalid,
		},
		{
			name:     "empty_username",
			Pat:      validatorTestPat,
			Username: "",
			expected: veles.ValidationInvalid,
			wantErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			usernamePat := dockerhubpat.DockerHubPAT{Pat: tc.Pat, Username: tc.Username}

			got, err := validator.Validate(t.Context(), usernamePat)

			if tc.wantErr {
				if err == nil {
					t.Errorf("Validate() expected error for %s, got nil", tc.name)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error for %s: %v", tc.name, err)
				}
				if got != tc.expected {
					t.Errorf("Validate() = %v, want %v for %s", got, tc.expected, tc.name)
				}
			}
		})
	}
}
