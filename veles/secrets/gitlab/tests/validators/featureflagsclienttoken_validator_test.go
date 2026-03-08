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
	"testing"

	"github.com/google/osv-scalibr/veles"
	gitlabsecrets "github.com/google/osv-scalibr/veles/secrets/gitlab"
)

func TestFeatureFlagsClientTokenValidator_Validate(t *testing.T) {
	tests := []struct {
		name           string
		token          gitlabsecrets.FeatureFlagsClientToken
		serverResponse int
		wantStatus     veles.ValidationStatus
		wantErr        bool
	}{
		{
			name: "valid_token_with_200_OK",
			token: gitlabsecrets.FeatureFlagsClientToken{
				Token:    "glffct-KH5TUFTqs5ysYsDxPz24",
				Endpoint: "https://gitlab.example.com/api/v4/feature_flags/unleash/79858780",
			},
			serverResponse: http.StatusOK,
			wantStatus:     veles.ValidationValid,
			wantErr:        false,
		},
		{
			name: "invalid_token_with_401_Unauthorized",
			token: gitlabsecrets.FeatureFlagsClientToken{
				Token:    "glffct-invalidtoken123",
				Endpoint: "https://gitlab.example.com/api/v4/feature_flags/unleash/79858780",
			},
			serverResponse: http.StatusUnauthorized,
			wantStatus:     veles.ValidationInvalid,
			wantErr:        false,
		},
		{
			name: "missing_Endpoint",
			token: gitlabsecrets.FeatureFlagsClientToken{
				Token: "glffct-KH5TUFTqs5ysYsDxPz24",
			},
			wantStatus: veles.ValidationFailed,
			wantErr:    true,
		},
		{
			name: "valid_token_different_project",
			token: gitlabsecrets.FeatureFlagsClientToken{
				Token:    "glffct-wwGhXf4qa_VYq7oHC7Xy",
				Endpoint: "https://gitlab.example.com/api/v4/feature_flags/unleash/12345678",
			},
			serverResponse: http.StatusOK,
			wantStatus:     veles.ValidationValid,
			wantErr:        false,
		},
		{
			name: "forbidden_response_404",
			token: gitlabsecrets.FeatureFlagsClientToken{
				Token:    "glffct-KH5TUFTqs5ysYsDxPz24",
				Endpoint: "https://gitlab.example.com/api/v4/feature_flags/unleash/99999999",
			},
			serverResponse: http.StatusNotFound,
			wantStatus:     veles.ValidationFailed,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server if we have a server response
			if tt.serverResponse != 0 {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Verify Authorization header
					authHeader := r.Header.Get("Authorization")
					if authHeader != tt.token.Token {
						t.Errorf("Expected Authorization header %q, got %q", tt.token.Token, authHeader)
					}

					// Return the configured response
					w.WriteHeader(tt.serverResponse)
				}))
				defer server.Close()

				// Update the token's endpoint to use the test server
				tt.token.Endpoint = server.URL
			}

			validator := gitlabsecrets.NewFeatureFlagsClientTokenValidator()
			gotStatus, err := validator.Validate(context.Background(), tt.token)

			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if gotStatus != tt.wantStatus {
				t.Errorf("Validate() status = %v, want %v", gotStatus, tt.wantStatus)
			}
		})
	}
}
