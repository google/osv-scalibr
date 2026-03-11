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

package databricks_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/databricks"
)

const (
	validatorTestClientID          = "client_id: 7603a2a8-8220-485f-b2a5-58fa7b60a932"
	validatorTestClientSecret      = "dose7d9f306280a357544b0655ed81ef06c9"
	validatorSPOAuth2ClientTestURL = "adb-myworkspace.1233322.azuredatabricks.net"
	expectedBase64Data             = "Y2xpZW50X2lkOiA3NjAzYTJhOC04MjIwLTQ4NWYtYjJhNS01OGZhN2I2MGE5MzI6ZG9zZTdkOWYzMDYyODBhMzU3NTQ0YjA2NTVlZDgxZWYwNmM5"
)

// mockSPOAuth2ClientTransport redirects requests to the test server
type mockSPOAuth2ClientTransport struct {
	testServer *httptest.Server
}

func (m *mockSPOAuth2ClientTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if strings.Contains(req.URL.Host, "adb-myworkspace.1233322.azuredatabricks.net") {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockSPOAuth2ClientDatabricksServer creates a mock Databricks server for testing
func mockSPOAuth2ClientDatabricksServer(t *testing.T, expectedBase64Data string, serverResponseCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a POST request to the expected endpoint
		if r.Method != http.MethodPost || r.URL.Path != "/oidc/v1/token" {
			t.Errorf("unexpected request: %s %s, expected: POST /oidc/v1/token", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		authHeader := r.Header.Get("Authorization")

		// Check Authorization header and Account-Id
		if !strings.Contains(authHeader, expectedBase64Data) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Set response
		w.WriteHeader(serverResponseCode)
	}))
}

func TestSPOAuth2ClientValidator(t *testing.T) {
	tests := []struct {
		name               string
		id                 string
		secret             string
		url                string
		serverResponseCode int
		cancelContext      bool
		want               veles.ValidationStatus
		wantErr            error
		useServer          bool
	}{
		{
			name:               "valid creds",
			id:                 validatorTestClientID,
			secret:             validatorTestClientSecret,
			url:                validatorSPOAuth2ClientTestURL,
			serverResponseCode: http.StatusOK,
			want:               veles.ValidationValid,
		},
		{
			name:               "invalid creds - Client ID",
			id:                 "YUVRAJ SAXENA",
			secret:             validatorTestClientSecret,
			url:                validatorSPOAuth2ClientTestURL,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "invalid creds - Client Secret",
			id:                 validatorTestClientID,
			secret:             "YUVRAJ SAXENA",
			url:                validatorSPOAuth2ClientTestURL,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "invalid creds - URL",
			id:                 validatorTestClientID,
			secret:             validatorTestClientSecret,
			url:                "YUVRAJ SAXENA",
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
		{
			name:               "empty Client ID",
			id:                 "",
			secret:             validatorTestClientSecret,
			url:                validatorSPOAuth2ClientTestURL,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "empty Client Secret",
			id:                 validatorTestClientID,
			secret:             "",
			url:                validatorSPOAuth2ClientTestURL,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "empty URL",
			id:                 validatorTestClientID,
			secret:             validatorTestClientSecret,
			url:                "",
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
		{
			name:               "context cancelled",
			id:                 validatorTestClientID,
			secret:             validatorTestClientSecret,
			url:                validatorSPOAuth2ClientTestURL,
			serverResponseCode: http.StatusOK,
			cancelContext:      true,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			server := mockSPOAuth2ClientDatabricksServer(t, expectedBase64Data, tt.serverResponseCode)
			defer server.Close()

			if tt.cancelContext {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			validator := databricks.NewSPOAuth2ClientValidator()
			if server != nil {
				validator.HTTPC = &http.Client{
					Transport: &mockSPOAuth2ClientTransport{testServer: server},
				}
			}

			cred := databricks.SPOAuth2ClientCredentials{
				URL:    tt.url,
				Secret: tt.secret,
				ID:     tt.id,
			}

			got, err := validator.Validate(ctx, cred)

			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
			}

			if got != tt.want {
				t.Fatalf("Validate: expected %v, got %v", tt.want, got)
			}
		})
	}
}
