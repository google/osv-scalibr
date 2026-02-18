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

package databricksserviceprincipalpat_test

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
	"github.com/google/osv-scalibr/veles/secrets/databricksserviceprincipalpat"
)

const (
	validatorTestToken = "dapiec91f46edff7a4ecae11005e2dcd21e5"
	validatorTestURL   = "my-workspace.gcp.databricks.com"
)

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if req.URL.Host == "my-workspace.gcp.databricks.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockDatabricksServer creates a mock Databricks server for testing
func mockDatabricksServer(t *testing.T, expectedToken string, serverResponseCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a POST request to the expected endpoint
		if r.Method != http.MethodPost || r.URL.Path != "/api/2.0/token/create" {
			t.Errorf("unexpected request: %s %s, expected: POST /api/2.0/token/create", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		authHeader := r.Header.Get("Authorization")

		// Check Authorization header and Account-Id
		if !strings.Contains(authHeader, expectedToken) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Set response
		w.WriteHeader(serverResponseCode)
	}))
}

func TestValidator(t *testing.T) {
	tests := []struct {
		name               string
		token              string
		url                string
		serverResponseCode int
		cancelContext      bool
		want               veles.ValidationStatus
		wantErr            error
	}{
		{
			name:               "valid creds",
			token:              validatorTestToken,
			url:                validatorTestURL,
			serverResponseCode: http.StatusOK,
			want:               veles.ValidationValid,
		},
		{
			name:               "invalid creds - Token",
			token:              "YUVRAJ SAXENA",
			url:                validatorTestURL,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "invalid creds - URL",
			token:              validatorTestToken,
			url:                "YUVRAJ SAXENA",
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
		{
			name:               "empty Token",
			token:              "",
			url:                validatorTestURL,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
		{
			name:               "empty URL",
			token:              validatorTestToken,
			url:                "",
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
		{
			name:               "context cancelled",
			token:              validatorTestToken,
			url:                validatorTestURL,
			serverResponseCode: http.StatusOK,
			cancelContext:      true,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			server := mockDatabricksServer(t, validatorTestToken, tt.serverResponseCode)
			defer server.Close()

			if tt.cancelContext {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			validator := databricksserviceprincipalpat.NewValidator()
			if server != nil {
				validator.HTTPC = &http.Client{
					Transport: &mockTransport{testServer: server},
				}
			}

			cred := databricksserviceprincipalpat.Credentials{
				Token: tt.token,
				URL:   tt.url,
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
