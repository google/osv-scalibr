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

package salesforceoauth2client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/salesforceoauth2client"
)

const validatorTestClientID = "3MVG123456789.AB_CDEF.ABC123456789ABC123456789ABC1"
const validatorTestClientSecret = "123456789ABCDEFABC1234567895123456789ABCDEFABC1234567895"
const validatorTestURL = "yuvrajapp.my.salesforce.com"
const validatorExpectedBase64Data = "M01WRzEyMzQ1Njc4OS5BQl9DREVGLkFCQzEyMzQ1Njc4OUFCQzEyMzQ1Njc4OUFCQzE6MTIzNDU2Nzg5QUJDREVGQUJDMTIzNDU2Nzg5NTEyMzQ1Njc4OUFCQ0RFRkFCQzEyMzQ1Njc4OTU="

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if req.URL.Host == validatorTestURL {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockSalesforceServer creates a mock Salesforce server for testing
func mockSalesforceServer(t *testing.T, expectedBase64Data string, serverResponseCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a POST request to the expected endpoint
		if r.Method != http.MethodPost || r.URL.Path != "/services/oauth2/token" {
			t.Errorf("unexpected request: %s %s, expected: POST /services/oauth2/token", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Authorization header
		authHeader := r.Header.Get("Authorization")
		if len(expectedBase64Data) > 0 && !strings.Contains(authHeader, expectedBase64Data) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Set response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(serverResponseCode)
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name                     string
		id                       string
		secret                   string
		url                      string
		serverExpectedBase64Data string
		serverResponseCode       int
		want                     veles.ValidationStatus
		expectError              bool
	}{
		{
			name:                     "valid creds",
			id:                       validatorTestClientID,
			secret:                   validatorTestClientSecret,
			url:                      validatorTestURL,
			serverExpectedBase64Data: validatorExpectedBase64Data,
			serverResponseCode:       http.StatusOK,
			want:                     veles.ValidationValid,
		},
		{
			name:                     "invalid creds - client_id",
			id:                       "YUVRAJ SAXENA",
			secret:                   validatorTestClientSecret,
			url:                      validatorTestURL,
			serverExpectedBase64Data: validatorExpectedBase64Data,
			serverResponseCode:       http.StatusUnauthorized,
			want:                     veles.ValidationInvalid,
		},
		{
			name:                     "invalid creds - client_secret",
			id:                       validatorTestClientID,
			secret:                   "YUVRAJ SAXENA",
			url:                      validatorTestURL,
			serverExpectedBase64Data: validatorExpectedBase64Data,
			serverResponseCode:       http.StatusUnauthorized,
			want:                     veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock server
			server := mockSalesforceServer(t, tc.serverExpectedBase64Data, tc.serverResponseCode)
			defer server.Close()

			// Create a client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create a validator with a mock client
			validator := salesforceoauth2client.NewValidator()
			validator.HTTPC = client

			// Create test credentials
			cred := salesforceoauth2client.Credentials{ID: tc.id, Secret: tc.secret, URL: tc.url}

			// Test validation
			got, err := validator.Validate(t.Context(), cred)

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

func TestValidator_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := salesforceoauth2client.NewValidator()
	validator.HTTPC = client

	// Create test credentials
	cred := salesforceoauth2client.Credentials{ID: validatorTestClientID, Secret: validatorTestClientSecret, URL: validatorTestURL}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Test validation with cancelled context
	got, err := validator.Validate(ctx, cred)

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

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := salesforceoauth2client.NewValidator()
	validator.HTTPC = client

	testCases := []struct {
		name     string
		id       string
		secret   string
		url      string
		expected veles.ValidationStatus
	}{
		{
			name:     "empty clientID",
			id:       "",
			secret:   validatorTestClientSecret,
			url:      validatorTestURL,
			expected: veles.ValidationInvalid,
		},
		{
			name:     "empty clientSecret",
			id:       validatorTestClientID,
			secret:   "",
			url:      validatorTestURL,
			expected: veles.ValidationInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test credentials
			cred := salesforceoauth2client.Credentials{ID: tc.id, Secret: tc.secret, URL: tc.url}

			got, err := validator.Validate(t.Context(), cred)

			if err != nil {
				t.Errorf("Validate() unexpected error for %s: %v", tc.name, err)
			}
			if got != tc.expected {
				t.Errorf("Validate() = %v, want %v for %s", got, tc.expected, tc.name)
			}
		})
	}
}
