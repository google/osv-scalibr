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

package sapoauth2client_test

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
	"github.com/google/osv-scalibr/veles/secrets/sapoauth2client"
)

const (
	validatorTestClientID     = "sb-cffc4197-e2bb-4a82-a127-8f202a3bb45c!b157978|it!b117912"
	validatorTestClientSecret = "client_secret: e602e1f0-dec1-45f5-8076-22508b2edb47$V8llAxOUna9EZRsVhWFk3zBkksspWrlF9ETuj2OZqr8="
	validatorTestTokenURL     = "figafpartner-1.authentication.eu10.hana.ondemand.com/oauth/token"
	validatorTestURL          = "figafpartner-1.it-cpi018.cfapps.eu10-003.hana.ondemand.com"
	expectedBase64Data        = "c2ItY2ZmYzQxOTctZTJiYi00YTgyLWExMjctOGYyMDJhM2JiNDVjIWIxNTc5Nzh8aXQhYjExNzkxMjpjbGllbnRfc2VjcmV0OiBlNjAyZTFmMC1kZWMxLTQ1ZjUtODA3Ni0yMjUwOGIyZWRiNDckVjhsbEF4T1VuYTlFWlJzVmhXRmszekJra3NzcFdybEY5RVR1ajJPWnFyOD0="
)

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if strings.Contains(req.URL.Host, validatorTestURL) {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockDatabricksServer creates a mock Databricks server for testing
func mockDatabricksServer(t *testing.T, expectedBase64Data string, serverResponseCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a POST request to the expected endpoint
		if r.Method != http.MethodPost || r.URL.Path != "/oauth/testConnectivity" {
			t.Errorf("unexpected request: %s %s, expected: POST /oauth/testConnectivity", r.Method, r.URL.Path)
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
		name               string
		id                 string
		secret             string
		tokenURL           string
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
			url:                validatorTestURL,
			tokenURL:           validatorTestTokenURL,
			serverResponseCode: http.StatusOK,
			want:               veles.ValidationValid,
		},
		{
			name:               "invalid creds - Client ID",
			id:                 "YUVRAJ SAXENA",
			secret:             validatorTestClientSecret,
			tokenURL:           validatorTestTokenURL,
			url:                validatorTestURL,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "invalid creds - Client Secret",
			id:                 validatorTestClientID,
			secret:             "YUVRAJ SAXENA",
			tokenURL:           validatorTestTokenURL,
			url:                validatorTestURL,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "invalid creds - URL",
			id:                 validatorTestClientID,
			secret:             validatorTestClientSecret,
			tokenURL:           validatorTestTokenURL,
			url:                "YUVRAJ SAXENA",
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
		{
			name:               "invalid creds - Token URL",
			id:                 validatorTestClientID,
			secret:             validatorTestClientSecret,
			tokenURL:           "YUVRAJ SAXENA",
			url:                validatorTestURL,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "empty Client ID",
			id:                 "",
			secret:             validatorTestClientSecret,
			tokenURL:           validatorTestTokenURL,
			url:                validatorTestURL,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "empty Client Secret",
			id:                 validatorTestClientID,
			secret:             "",
			tokenURL:           validatorTestTokenURL,
			url:                validatorTestURL,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "empty URL",
			id:                 validatorTestClientID,
			secret:             validatorTestClientSecret,
			tokenURL:           validatorTestTokenURL,
			url:                "",
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
		{
			name:               "empty Token URL",
			id:                 validatorTestClientID,
			secret:             validatorTestClientSecret,
			tokenURL:           "",
			url:                validatorTestURL,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "context cancelled",
			id:                 validatorTestClientID,
			secret:             validatorTestClientSecret,
			tokenURL:           validatorTestTokenURL,
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

			server := mockDatabricksServer(t, expectedBase64Data, tt.serverResponseCode)
			defer server.Close()

			if tt.cancelContext {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			validator := sapoauth2client.NewValidator()
			if server != nil {
				validator.HTTPC = &http.Client{
					Transport: &mockTransport{testServer: server},
				}
			}

			cred := sapoauth2client.Credentials{
				ID:       tt.id,
				Secret:   tt.secret,
				TokenURL: tt.tokenURL,
				URL:      tt.url,
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
