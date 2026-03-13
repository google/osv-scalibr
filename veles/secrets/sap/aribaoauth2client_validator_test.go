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
	expectedBase64SAPAribaData = "Y2xpZW50X2lkOiBzN2JhZmFlZi0wMTZhLTQ0MjYtOGQwNS04MjI4ZmNmNGRkYzk6Y2xpZW50X3NlY3JldDogR2w5RTVzc2YyTFY1QU5VWTNLMlk3Z29xdVNzUDJ5OEY="
)

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if strings.Contains(req.URL.Host, "ariba") {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockSAPAribaServer creates a mock SAP server for testing
func mockSAPAribaServer(t *testing.T, expectedBase64SAPAribaData string, serverResponseCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a POST request to the expected endpoint
		if r.Method != http.MethodPost || r.URL.Path != "/v2/oauth/token" {
			t.Errorf("unexpected request: %s %s, expected: POST /v2/oauth/token", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Authorization header
		authHeader := r.Header.Get("Authorization")
		if len(expectedBase64SAPAribaData) > 0 && !strings.Contains(authHeader, expectedBase64SAPAribaData) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Set response
		w.WriteHeader(serverResponseCode)
	}))
}

func TestSAPAribaOAuth2ClientCredentialsValidator(t *testing.T) {
	tests := []struct {
		name               string
		id                 string
		secret             string
		serverResponseCode int
		cancelContext      bool
		want               veles.ValidationStatus
		wantErr            error
		useServer          bool
	}{
		{
			name:               "valid creds",
			id:                 "client_id: " + validSAPAribaClientID,
			secret:             "client_secret: " + validSAPAribaClientSecret,
			serverResponseCode: http.StatusOK,
			want:               veles.ValidationValid,
		},
		{
			name:               "invalid creds - Client ID",
			id:                 "YUVRAJ SAXENA",
			secret:             "client_secret: " + validSAPAribaClientSecret,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "invalid creds - Client Secret",
			id:                 "client_id: " + validSAPAribaClientID,
			secret:             "YUVRAJ SAXENA",
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "empty Client ID",
			id:                 "",
			secret:             "client_secret: " + validSAPAribaClientSecret,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "empty Client Secret",
			id:                 "client_id: " + validSAPAribaClientID,
			secret:             "",
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "context cancelled",
			id:                 "client_id: " + validSAPAribaClientID,
			secret:             "client_secret: " + validSAPAribaClientSecret,
			serverResponseCode: http.StatusOK,
			cancelContext:      true,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			server := mockSAPAribaServer(t, expectedBase64SAPAribaData, tt.serverResponseCode)
			defer server.Close()

			if tt.cancelContext {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			validator := sap.NewSAPAribaOAuth2ClientCredentialsValidator()
			if server != nil {
				validator.HTTPC = &http.Client{
					Transport: &mockTransport{testServer: server},
				}
			}

			cred := sap.AribaOAuth2ClientCredentials{
				ID:     tt.id,
				Secret: tt.secret,
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
