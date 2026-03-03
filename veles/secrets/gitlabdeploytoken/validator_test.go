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

package gitlabdeploytoken_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/gitlab"
	"github.com/google/osv-scalibr/veles/secrets/gitlabdeploytoken"
)

func TestValidator_Validate(t *testing.T) {
	tests := []struct {
		name           string
		token          gitlabdeploytoken.GitlabDeployToken
		serverResponse int
		wantStatus     veles.ValidationStatus
		wantErr        bool
	}{
		{
			name: "valid_token_with_200_OK",
			token: gitlabdeploytoken.GitlabDeployToken{
				Token:    "gldt-validtoken123456",
				Username: "gitlab+deploy-token-12345",
				RepoURL:  "https://gitlab.example.com/testgroup/testproject.git",
			},
			serverResponse: http.StatusOK,
			wantStatus:     veles.ValidationValid,
			wantErr:        false,
		},
		{
			name: "valid_token_with_403_Forbidden",
			token: gitlabdeploytoken.GitlabDeployToken{
				Token:    "gldt-validtoken123456",
				Username: "gitlab+deploy-token-12345",
				RepoURL:  "https://gitlab.example.com/testgroup/testproject.git",
			},
			serverResponse: http.StatusForbidden,
			wantStatus:     veles.ValidationValid,
			wantErr:        false,
		},
		{
			name: "invalid_token_with_401_Unauthorized",
			token: gitlabdeploytoken.GitlabDeployToken{
				Token:    "gldt-invalidtoken123",
				Username: "gitlab+deploy-token-12345",
				RepoURL:  "https://gitlab.example.com/testgroup/testproject.git",
			},
			serverResponse: http.StatusUnauthorized,
			wantStatus:     veles.ValidationInvalid,
			wantErr:        false,
		},
		{
			name: "repository_not_found_with_404",
			token: gitlabdeploytoken.GitlabDeployToken{
				Token:    "gldt-validtoken123456",
				Username: "gitlab+deploy-token-12345",
				RepoURL:  "https://gitlab.example.com/nonexistent/project.git",
			},
			serverResponse: http.StatusNotFound,
			wantStatus:     veles.ValidationFailed,
			wantErr:        true,
		},
		{
			name: "missing_RepoURL",
			token: gitlabdeploytoken.GitlabDeployToken{
				Token:    "gldt-validtoken123456",
				Username: "gitlab+deploy-token-12345",
			},
			wantStatus: veles.ValidationFailed,
			wantErr:    true,
		},
		{
			name: "invalid_RepoURL_format",
			token: gitlabdeploytoken.GitlabDeployToken{
				Token:    "gldt-validtoken123456",
				Username: "gitlab+deploy-token-12345",
				RepoURL:  "not-a-valid-url",
			},
			wantStatus: veles.ValidationFailed,
			wantErr:    true,
		},
		{
			name: "RepoURL_with_only_one_path_segment",
			token: gitlabdeploytoken.GitlabDeployToken{
				Token:    "gldt-validtoken123456",
				Username: "gitlab+deploy-token-12345",
				RepoURL:  "https://gitlab.example.com/onlyone.git",
			},
			wantStatus: veles.ValidationFailed,
			wantErr:    true,
		},
		{
			name: "SSH_scp-style_URL_validation",
			token: gitlabdeploytoken.GitlabDeployToken{
				Token:    "gldt-validtoken123456",
				Username: "gitlab+deploy-token-12345",
				RepoURL:  "git@gitlab.example.com:testgroup/testproject.git",
			},
			serverResponse: http.StatusOK,
			wantStatus:     veles.ValidationValid,
			wantErr:        false,
		},
		{
			name: "nested_subgroups_validation",
			token: gitlabdeploytoken.GitlabDeployToken{
				Token:    "gldt-validtoken123456",
				Username: "gitlab+deploy-token-12345",
				RepoURL:  "https://gitlab.example.com/org/team/backend/service.git",
			},
			serverResponse: http.StatusOK,
			wantStatus:     veles.ValidationValid,
			wantErr:        false,
		},
		{
			name: "SSH_URL-style_validation",
			token: gitlabdeploytoken.GitlabDeployToken{
				Token:    "gldt-validtoken123456",
				Username: "gitlab+deploy-token-12345",
				RepoURL:  "ssh://git@gitlab.example.com/group/project.git",
			},
			serverResponse: http.StatusOK,
			wantStatus:     veles.ValidationValid,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server if we have a server response
			if tt.serverResponse != 0 {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Verify query parameter
					if r.URL.Query().Get("service") != "git-upload-pack" {
						t.Errorf("unexpected service parameter: got %q, want %q",
							r.URL.Query().Get("service"), "git-upload-pack")
					}

					// Verify Basic Auth
					username, password, ok := r.BasicAuth()
					if !ok {
						t.Error("missing Basic Auth")
					}
					if username != tt.token.Username {
						t.Errorf("unexpected username: got %q, want %q", username, tt.token.Username)
					}
					if password != tt.token.Token {
						t.Errorf("unexpected password: got %q, want %q", password, tt.token.Token)
					}

					w.WriteHeader(tt.serverResponse)
				}))
				defer server.Close()

				// Update the token RepoURL to point to the test server
				// Parse the original RepoURL to get namespace and project
				info := gitlab.ParseRepoURL(tt.token.RepoURL)
				if info != nil {
					// Reconstruct URL with test server hostname
					serverHost := server.URL[7:] // Remove "http://"
					tt.token.RepoURL = fmt.Sprintf("http://%s/%s/%s.git", serverHost, info.Namespace, info.Project)
				}
			}

			validator := gitlabdeploytoken.NewValidator()
			status, err := validator.Validate(context.Background(), tt.token)

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
