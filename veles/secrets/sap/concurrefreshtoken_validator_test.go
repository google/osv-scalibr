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

// mockSAPConcurRefreshTokenTransport redirects requests to the test server
type mockSAPConcurRefreshTokenTransport struct {
	testServer *httptest.Server
}

func (m *mockSAPConcurRefreshTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if strings.Contains(req.URL.Host, "concur") {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockSAPConcurRefreshTokenServer creates a mock SAP Concur server for testing
func mockSAPConcurRefreshTokenServer(t *testing.T, expectedSAPConcurClientID string, expectedSAPConcurClientSecret string, expectedSAPConcurRefreshToken string, serverResponseCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a POST request to the expected endpoint
		if r.Method != http.MethodPost || r.URL.Path != "/oauth2/v0/token" {
			t.Errorf("unexpected request: %s %s, expected: POST /oauth2/v0/token", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Parse form body
		if err := r.ParseForm(); err != nil {
			t.Errorf("failed to parse request body: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		clientID := r.Form.Get("client_id")
		clientSecret := r.Form.Get("client_secret")
		refreshToken := r.Form.Get("refresh_token")

		// Validate request body
		if !strings.Contains(clientID, expectedSAPConcurClientID) ||
			!strings.Contains(clientSecret, expectedSAPConcurClientSecret) ||
			!strings.Contains(refreshToken, expectedSAPConcurRefreshToken) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Set response
		w.WriteHeader(serverResponseCode)
	}))
}

func TestSAPConcurRefreshTokenValidator(t *testing.T) {
	tests := []struct {
		name               string
		id                 string
		secret             string
		token              string
		serverResponseCode int
		cancelContext      bool
		want               veles.ValidationStatus
		wantErr            error
		useServer          bool
	}{
		{
			name:               "valid creds",
			id:                 "client_id: " + validSAPAribaClientID,
			secret:             "client_secret: " + validSAPConcurClientSecret,
			token:              "refresh_token: " + validSAPConcurRefreshToken,
			serverResponseCode: http.StatusOK,
			want:               veles.ValidationValid,
		},
		{
			name:               "invalid creds - Client ID",
			id:                 "YUVRAJ SAXENA",
			secret:             "client_secret: " + validSAPConcurClientSecret,
			token:              "refresh_token: " + validSAPConcurRefreshToken,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "invalid creds - Client Secret",
			id:                 "client_id: " + validSAPAribaClientID,
			secret:             "YUVRAJ SAXENA",
			token:              "refresh_token: " + validSAPConcurRefreshToken,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "invalid creds - Refresh Token",
			id:                 "client_id: " + validSAPAribaClientID,
			secret:             "YUVRAJ SAXENA",
			token:              "refresh_token: A-B",
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "empty Client ID",
			id:                 "",
			secret:             "client_secret: " + validSAPConcurClientSecret,
			token:              "refresh_token: " + validSAPConcurRefreshToken,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "empty Client Secret",
			id:                 "client_id: " + validSAPAribaClientID,
			secret:             "",
			token:              "refresh_token: " + validSAPConcurRefreshToken,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "empty Refresh Token",
			id:                 "client_id: " + validSAPAribaClientID,
			secret:             validSAPConcurClientSecret,
			token:              "",
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "context cancelled",
			id:                 "client_id: " + validSAPAribaClientID,
			secret:             "client_secret: " + validSAPConcurClientSecret,
			serverResponseCode: http.StatusOK,
			cancelContext:      true,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			server := mockSAPConcurRefreshTokenServer(t, validSAPAribaClientID, validSAPConcurClientSecret, validSAPConcurRefreshToken, tt.serverResponseCode)
			defer server.Close()

			if tt.cancelContext {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			validator := sap.NewSAPConcurRefreshTokenValidator()
			if server != nil {
				validator.HTTPC = &http.Client{
					Transport: &mockSAPConcurRefreshTokenTransport{testServer: server},
				}
			}

			cred := sap.ConcurRefreshToken{
				ID:     tt.id,
				Secret: tt.secret,
				Token:  tt.token,
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
