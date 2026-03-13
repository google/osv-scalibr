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

package sap_test

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
	"github.com/google/osv-scalibr/veles/secrets/sap"
)

const (
	expectedBase64Data      = "c2ItY2ZmYzQxOTctZTJiYi00YTgyLWExMjctOGYyMDJhM2JiNDVjIWIxNTc5Nzh8aXQhYjExNzkxMjpjbGllbnRfc2VjcmV0OiBlNjAyZTFmMC1kZWMxLTQ1ZjUtODA3Ni0yMjUwOGIyZWRiNDckVjhsbEF4T1VuYTlFWlJzVmhXRmszekJra3NzcFdybEY5RVR1ajJPWnFyOD0="
	expectedXSUAABase64Data = "c2ItbXlhcHBkZW1vIWIxNTc5Nzg6Y2xpZW50X3NlY3JldDogZTYwMmUxZjAtZGVjMS00NWY1LTgwNzYtMjI1MDhiMmVkYjQ3JFY4bGxBeE9VbmE5RVpSc1ZoV0ZrM3pCa2tzc3BXcmxGOUVUdWoyT1pxcjg9"
)

// mockSAPBTPTransport redirects requests to the test server
type mockSAPBTPTransport struct {
	testServer *httptest.Server
}

func (m *mockSAPBTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if strings.Contains(req.URL.Host, "hana.ondemand.com") {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockSAPBTPServer creates a mock SAP BTP server for testing
func mockSAPBTPServer(t *testing.T, expectedBase64Data string, serverResponseCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a POST request to the expected endpoint
		if r.Method != http.MethodPost || r.URL.Path != "/oauth/token" {
			t.Errorf("unexpected request: %s %s, expected: POST /oauth/token", r.Method, r.URL.Path)
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
		w.WriteHeader(serverResponseCode)
	}))
}

func TestSAPBTPValidator(t *testing.T) {
	tests := []struct {
		name               string
		id                 string
		secret             string
		tokenURL           string
		serverResponseCode int
		cancelContext      bool
		want               veles.ValidationStatus
		wantErr            error
		useServer          bool
	}{
		{
			name:               "valid creds",
			id:                 validBTPClientID,
			secret:             "client_secret: " + validBTPClientSecret,
			tokenURL:           validBTPTokenURL,
			serverResponseCode: http.StatusOK,
			want:               veles.ValidationValid,
		},
		{
			name:               "valid creds - BTP XSUAA",
			id:                 validBTPXSUAAClientID,
			secret:             "client_secret: " + validBTPClientSecret,
			tokenURL:           validBTPTokenURL,
			serverResponseCode: http.StatusOK,
			want:               veles.ValidationValid,
		},
		{
			name:               "invalid creds - Client ID",
			id:                 "YUVRAJ SAXENA",
			secret:             "client_secret: " + validBTPClientSecret,
			tokenURL:           validBTPTokenURL,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "invalid creds - Client Secret",
			id:                 validBTPClientID,
			secret:             "YUVRAJ SAXENA",
			tokenURL:           validBTPTokenURL,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "invalid creds - Token URL",
			id:                 validBTPClientID,
			secret:             "client_secret: " + validBTPClientSecret,
			tokenURL:           "YUVRAJ SAXENA",
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
		{
			name:               "empty Client ID",
			id:                 "",
			secret:             "client_secret: " + validBTPClientSecret,
			tokenURL:           validBTPTokenURL,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "empty Client Secret",
			id:                 validBTPClientID,
			secret:             "",
			tokenURL:           validBTPTokenURL,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "empty Token URL",
			id:                 validBTPClientID,
			secret:             "client_secret: " + validBTPClientSecret,
			tokenURL:           "",
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
		{
			name:               "context cancelled",
			id:                 validBTPClientID,
			secret:             "client_secret: " + validBTPClientSecret,
			tokenURL:           validBTPTokenURL,
			serverResponseCode: http.StatusOK,
			cancelContext:      true,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			var server *httptest.Server
			if strings.Contains(tt.name, "XSUAA") {
				server = mockSAPBTPServer(t, expectedXSUAABase64Data, tt.serverResponseCode)
			} else {
				server = mockSAPBTPServer(t, expectedBase64Data, tt.serverResponseCode)
			}
			defer server.Close()

			if tt.cancelContext {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			validator := sap.NewBTPOAuth2ClientCredentialsValidator()
			if server != nil {
				validator.HTTPC = &http.Client{
					Transport: &mockSAPBTPTransport{testServer: server},
				}
			}

			cred := sap.BTPOAuth2ClientCredentials{
				ID:       tt.id,
				Secret:   tt.secret,
				TokenURL: tt.tokenURL,
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
