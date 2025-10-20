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

package deepseekapikey_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/deepseekapikey"
)

func TestAPIValidator_Validate(t *testing.T) {
	cases := []struct {
		name           string
		apiKey         string
		httpStatus     int
		responseBody   string
		expectedStatus veles.ValidationStatus
		expectError    bool
	}{{
		name:           "valid_key",
		apiKey:         "sk-15ac903f2e481u3d4f9g2u3ia8e2b73n",
		httpStatus:     http.StatusOK,
		responseBody:   `{"choices":[{"message":{"content":"Hello! How can I help you?"}}]}`,
		expectedStatus: veles.ValidationValid,
		expectError:    false,
	}, {
		name:           "invalid_key",
		apiKey:         "sk-invalid1234567890123456789012345678",
		httpStatus:     http.StatusUnauthorized,
		responseBody:   `{"error":{"message":"Invalid API key"}}`,
		expectedStatus: veles.ValidationInvalid,
		expectError:    false,
	}, {
		name:           "rate_limited",
		apiKey:         "sk-15ac903f2e481u3d4f9g2u3ia8e2b73n",
		httpStatus:     http.StatusTooManyRequests,
		responseBody:   `{"error":{"message":"Rate limit exceeded"}}`,
		expectedStatus: veles.ValidationValid,
		expectError:    false,
	}, {
		name:           "payment_required",
		apiKey:         "sk-15ac903f2e481u3d4f9g2u3ia8e2b73n",
		httpStatus:     http.StatusPaymentRequired,
		responseBody:   `{"error":{"message":"Payment required or quota exceeded"}}`,
		expectedStatus: veles.ValidationValid,
		expectError:    false,
	}, {
		name:           "forbidden",
		apiKey:         "sk-15ac903f2e481u3d4f9g2u3ia8e2b73n",
		httpStatus:     http.StatusForbidden,
		responseBody:   `{"error":{"message":"Insufficient permissions"}}`,
		expectedStatus: veles.ValidationValid,
		expectError:    false,
	}, {
		name:           "server_error",
		apiKey:         "sk-15ac903f2e481u3d4f9g2u3ia8e2b73n",
		httpStatus:     http.StatusInternalServerError,
		responseBody:   `{"error":{"message":"Internal server error"}}`,
		expectedStatus: veles.ValidationFailed,
		expectError:    true,
	}, {
		name:           "empty_key",
		apiKey:         "",
		httpStatus:     http.StatusOK,
		responseBody:   "",
		expectedStatus: veles.ValidationFailed,
		expectError:    true,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify the request headers and method
				if r.Method != http.MethodPost {
					t.Errorf("Expected POST request, got %s", r.Method)
				}

				if r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("Expected Content-Type: application/json, got %q",
						r.Header.Get("Content-Type"))
				}

				if tc.apiKey != "" {
					expectedAuth := "Bearer " + tc.apiKey
					if r.Header.Get("Authorization") != expectedAuth {
						t.Errorf("Expected Authorization: %q, got %q",
							expectedAuth, r.Header.Get("Authorization"))
					}
				}

				// Return the test response
				w.WriteHeader(tc.httpStatus)
				w.Write([]byte(tc.responseBody))
			}))
			defer server.Close()

			// Create validator with test server URL
			validator := deepseekapikey.NewAPIValidator(
				deepseekapikey.WithAPIURL(server.URL),
			)

			// Test the validation
			apiKey := deepseekapikey.APIKey{Key: tc.apiKey}
			status, err := validator.Validate(context.Background(), apiKey)

			// Check error expectation
			if tc.expectError && err == nil {
				t.Errorf("Expected error, but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Check status
			if status != tc.expectedStatus {
				t.Errorf("Expected status %v, got %v", tc.expectedStatus, status)
			}
		})
	}
}

func TestAPIValidator_ValidateRequestFormat(t *testing.T) {
	// This test verifies that the request format matches what DeepSeek expects
	var capturedRequest *http.Request
	var capturedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRequest = r
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		capturedBody = buf

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"content":"Test response"}}]}`))
	}))
	defer server.Close()

	validator := deepseekapikey.NewAPIValidator(
		deepseekapikey.WithAPIURL(server.URL),
	)

	apiKey := deepseekapikey.APIKey{Key: "sk-15ac903f2e481u3d4f9g2u3ia8e2b73n"}
	_, err := validator.Validate(context.Background(), apiKey)

	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	// Verify request path
	if capturedRequest.URL.Path != "/chat/completions" {
		t.Errorf("Expected path /chat/completions, got %s", capturedRequest.URL.Path)
	}

	// Verify request body contains expected fields
	bodyStr := string(capturedBody)
	expectedFields := []string{
		`"model":"deepseek-chat"`,
		`"role":"system"`,
		`"role":"user"`,
		`"content":"You are a helpful assistant."`,
		`"content":"Hello!"`,
		`"stream":false`,
	}

	for _, field := range expectedFields {
		if !strings.Contains(bodyStr, field) {
			t.Errorf("Request body missing expected field: %q\nBody: %q",
				field, bodyStr)
		}
	}
}
