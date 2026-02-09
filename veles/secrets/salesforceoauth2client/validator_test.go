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
		// ű if it's a POST request to the expected endpoint
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
	tests := []struct {
		name                     string
		id                       string
		secret                   string
		url                      string
		serverExpectedBase64Data string
		serverResponseCode       int
		cancelContext            bool
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
		{
			name:               "empty client_id",
			id:                 "",
			secret:             validatorTestClientSecret,
			url:                validatorTestURL,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "empty client_secret",
			id:                 validatorTestClientID,
			secret:             "",
			url:                validatorTestURL,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:                     "context cancelled",
			id:                       validatorTestClientID,
			secret:                   validatorTestClientSecret,
			url:                      validatorTestURL,
			serverExpectedBase64Data: validatorExpectedBase64Data,
			serverResponseCode:       http.StatusOK,
			cancelContext:            true,
			want:                     veles.ValidationFailed,
			expectError:              true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			// Create mock server
			server := mockSalesforceServer(t, tt.serverExpectedBase64Data, tt.serverResponseCode)
			defer server.Close()

			if tt.cancelContext {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			validator := salesforceoauth2client.NewValidator()
			validator.HTTPC = &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			cred := salesforceoauth2client.Credentials{
				ID:     tt.id,
				Secret: tt.secret,
				URL:    tt.url,
			}

			got, err := validator.Validate(ctx, cred)

			if tt.expectError && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}
