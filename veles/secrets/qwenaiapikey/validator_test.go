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

package qwenaiapikey_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/qwenaiapikey"
)

const (
	validatorTestKey = "sk-2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c"
)

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL for DashScope API.
	if strings.Contains(req.URL.Host, "aliyuncs.com") {
		// Just parse the test server URL and replace scheme/host
		// We don't need full parsing since we know it's a test server
		req.URL.Scheme = "http"
		req.URL.Host = m.testServer.Listener.Addr().String()
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockDashScopeAPIServer creates a mock DashScope generation endpoint for testing
// validators.
func mockDashScopeAPIServer(t *testing.T, expectedKey string, statusCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Expect a POST to /api/v1/services/aigc/text-generation/generation
		if r.Method != http.MethodPost || !strings.Contains(r.URL.Path, "/generation") {
			t.Errorf("unexpected request: %s %s, expected: POST .../generation", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Authorization header
		auth := r.Header.Get("Authorization")
		expectedAuth := "Bearer " + expectedKey
		if auth != expectedAuth {
			t.Errorf("expected Authorization header %q, got: %q", expectedAuth, auth)
		}

		w.WriteHeader(statusCode)
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name        string
		statusCode  int
		want        veles.ValidationStatus
		expectError bool
	}{
		{
			name:       "valid_key_bad_request",
			statusCode: http.StatusBadRequest, // 400 means auth passed but body failed -> Valid secret
			want:       veles.ValidationValid,
		},
		{
			name:       "valid_key_ok",
			statusCode: http.StatusOK, // 200 also means valid
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
			name:        "server_error",
			statusCode:  http.StatusInternalServerError,
			want:        veles.ValidationFailed,
			expectError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server
			server := mockDashScopeAPIServer(t, validatorTestKey, tc.statusCode)
			defer server.Close()

			// Create client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create validator with mock client
			validator := qwenaiapikey.NewValidator()
			validator.HTTPC = client

			// Create test key
			key := qwenaiapikey.QwenAIAPIKey{Key: validatorTestKey}

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
