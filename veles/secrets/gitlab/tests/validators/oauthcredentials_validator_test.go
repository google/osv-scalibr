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

package gitlab_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/veles"
	gitlabsecrets "github.com/google/osv-scalibr/veles/secrets/gitlab"
)

func TestOAuthCredentialsValidator_Validate(t *testing.T) {
	tests := []struct {
		name           string
		credentials    gitlabsecrets.OAuthCredentials
		serverResponse int
		wantStatus     veles.ValidationStatus
		wantErr        bool
	}{
		{
			name: "valid_credentials_with_400_bad_request",
			credentials: gitlabsecrets.OAuthCredentials{
				ClientID:     "9bedc237a4666df945257eb69a20ed9e53b64166fe9abb3f79c9f7ba42c4355f",
				ClientSecret: "gloas-cff41fbbd4212f7dfe05907bfb8a494f44b31e5966722a3563149946817f76c0",
			},
			serverResponse: http.StatusBadRequest,
			wantStatus:     veles.ValidationValid,
			wantErr:        false,
		},
		{
			name: "invalid_credentials_with_401_unauthorized",
			credentials: gitlabsecrets.OAuthCredentials{
				ClientID:     "invalidclientid1234567890abcdef1234567890abcdef1234567890abcdef",
				ClientSecret: "gloas-invalidclientsecret1234567890abcdef1234567890abcdef1234567890ab",
			},
			serverResponse: http.StatusUnauthorized,
			wantStatus:     veles.ValidationInvalid,
			wantErr:        false,
		},
		{
			name: "valid_credentials_with_self_hosted_instance",
			credentials: gitlabsecrets.OAuthCredentials{
				ClientID:     "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				ClientSecret: "gloas-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			},
			serverResponse: http.StatusBadRequest,
			wantStatus:     veles.ValidationValid,
			wantErr:        false,
		},
		{
			name: "unexpected_response_code_500",
			credentials: gitlabsecrets.OAuthCredentials{
				ClientID:     "9bedc237a4666df945257eb69a20ed9e53b64166fe9abb3f79c9f7ba42c4355f",
				ClientSecret: "gloas-cff41fbbd4212f7dfe05907bfb8a494f44b31e5966722a3563149946817f76c0",
			},
			serverResponse: http.StatusInternalServerError,
			wantStatus:     veles.ValidationFailed,
			wantErr:        true,
		},
		{
			name: "missing_client_id",
			credentials: gitlabsecrets.OAuthCredentials{
				ClientSecret: "gloas-cff41fbbd4212f7dfe05907bfb8a494f44b31e5966722a3563149946817f76c0",
			},
			wantStatus: veles.ValidationFailed,
			wantErr:    true,
		},
		{
			name: "missing_client_secret",
			credentials: gitlabsecrets.OAuthCredentials{
				ClientID: "9bedc237a4666df945257eb69a20ed9e53b64166fe9abb3f79c9f7ba42c4355f",
			},
			wantStatus: veles.ValidationFailed,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server if we have a server response
			if tt.serverResponse != 0 {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Verify the request is a POST to /oauth/token
					if r.Method != http.MethodPost {
						t.Errorf("unexpected HTTP method: got %q, want %q", r.Method, http.MethodPost)
					}

					if !strings.HasSuffix(r.URL.Path, "/oauth/token") {
						t.Errorf("unexpected URL path: got %q, want suffix %q", r.URL.Path, "/oauth/token")
					}

					// Verify Content-Type header
					contentType := r.Header.Get("Content-Type")
					if contentType != "application/x-www-form-urlencoded" {
						t.Errorf("unexpected Content-Type: got %q, want %q", contentType, "application/x-www-form-urlencoded")
					}

					// Parse form data
					if err := r.ParseForm(); err != nil {
						t.Errorf("failed to parse form: %v", err)
					}

					// Verify form parameters
					if r.FormValue("client_id") != tt.credentials.ClientID {
						t.Errorf("unexpected client_id: got %q, want %q", r.FormValue("client_id"), tt.credentials.ClientID)
					}
					if r.FormValue("client_secret") != tt.credentials.ClientSecret {
						t.Errorf("unexpected client_secret: got %q, want %q", r.FormValue("client_secret"), tt.credentials.ClientSecret)
					}
					if r.FormValue("grant_type") != "authorization_code" {
						t.Errorf("unexpected grant_type: got %q, want %q", r.FormValue("grant_type"), "authorization_code")
					}

					w.WriteHeader(tt.serverResponse)
				}))
				defer server.Close()

				// Use the test server URL directly (it's already HTTP)
				tt.credentials.Hostname = strings.TrimPrefix(server.URL, "http://")
			}

			validator := gitlabsecrets.NewOAuthCredentialsValidator()
			status, err := validator.Validate(context.Background(), tt.credentials)

			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if status != tt.wantStatus {
				t.Errorf("Validate() status = %v, want %v", status, tt.wantStatus)
			}
		})
	}
}
