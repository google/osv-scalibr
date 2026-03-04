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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gitlabdeploytoken"
)

func TestDetector_FindSecrets(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name: "valid_deploy_token_with_hostname_and_username",
			input: `
				url = https://gitlab.com/repo.git
				username = gitlab+deploy-token-12535871
				password = gldt-W6xaS96Cxzb87K5XsdAh
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Username: "username = gitlab+deploy-token-12535871",
					Token:    "gldt-W6xaS96Cxzb87K5XsdAh",
					RepoURL:  "https://gitlab.com/repo.git",
				},
			},
		},
		{
			name: "valid_deploy_token_with_repository_URL",
			input: `
				url = https://gitlab.com/test4701309/test-project.git
				username = gitlab+deploy-token-12535871
				password = gldt-W6xaS96Cxzb87K5XsdAh
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Username: "username = gitlab+deploy-token-12535871",
					Token:    "gldt-W6xaS96Cxzb87K5XsdAh",
					RepoURL:  "https://gitlab.com/test4701309/test-project.git",
				},
			},
		},
		{
			name: "valid_deploy_token_with_nested_group",
			input: `
				https://gitlab.example.com/org/backend/api-service.git
				username: testusername
				token: gldt-k3tx_ycYvssk_8FLUHju
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Username: "username: testusername",
					Token:    "gldt-k3tx_ycYvssk_8FLUHju",
					RepoURL:  "https://gitlab.example.com/org/backend/api-service.git",
				},
			},
		},
		{
			name: "valid_deploy_token_with_SSH_URL",
			input: `
				git@gitlab.com:mygroup/myproject.git
				username: myusername
				gldt-AbCdEfGhIjKlMnOpQrStUvWxYz123
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Username: "username: myusername",
					Token:    "gldt-AbCdEfGhIjKlMnOpQrStUvWxYz123",
					RepoURL:  "git@gitlab.com:mygroup/myproject.git",
				},
			},
		},
		{
			name: "valid deploy_token_with_SSH_URL_and_nested_groups",
			input: `
				git@gitlab.example.com:org/team/backend/service.git
				username: deploy_username
				gldt-W6xaS96Cxzb87K5XsdAh
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Username: "username: deploy_username",
					Token:    "gldt-W6xaS96Cxzb87K5XsdAh",
					RepoURL:  "git@gitlab.example.com:org/team/backend/service.git",
				},
			},
		},
		{
			name: "valid_deploy_token_with_username_only",
			input: `
				username = gitlab+deploy-token-12535884
				password = gldt-z6bNg4ZFGTAxf3GSpdiBgitlab
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Token: "gldt-z6bNg4ZFGTAxf3GSpdiBgitlab",
				},
			},
		},
		{
			name: "token_with_underscores",
			input: `
				user: gitlab+deploy-token-12535891
				token: gldt-k3tx_ycYvssk_8FLUHju
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Token: "gldt-k3tx_ycYvssk_8FLUHju",
				},
			},
		},
		{
			name: "self-hosted_gitlab_instance",
			input: `
				https://gitlab.example.com/testgroup/testproject.git
				username: gitlab+deploy-token-99999999
				gldt-AbCdEfGhIjKlMnOpQrStUvWxYz123
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Username: "username: gitlab+deploy-token-99999999",
					Token:    "gldt-AbCdEfGhIjKlMnOpQrStUvWxYz123",
					RepoURL:  "https://gitlab.example.com/testgroup/testproject.git",
				},
			},
		},
		{
			name: "generic_username_with_keyword_-_username_key-value",
			input: `
				username: thisisausername123
				password: gldt-k3tx_ycYvssk_8FLUHju
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Token: "gldt-k3tx_ycYvssk_8FLUHju",
				},
			},
		},
		{
			name: "generic_username_-_user_key-value",
			input: `
				user: myusername
				password: gldt-W6xaS96Cxzb87K5XsdAh
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Token: "gldt-W6xaS96Cxzb87K5XsdAh",
				},
			},
		},
		{
			name: "generic_username_-_equals_sign",
			input: `
				username=testuser
				password=gldt-z6bNg4ZFGTAxf3GSpdiBgitlab
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Token: "gldt-z6bNg4ZFGTAxf3GSpdiBgitlab",
				},
			},
		},
		{
			name: "generic_username_-_login_key-value",
			input: `
				login: deploy_username
				password: gldt-AbCdEfGhIjKlMnOpQrStUvWxYz123
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Token: "gldt-AbCdEfGhIjKlMnOpQrStUvWxYz123",
				},
			},
		},
		{
			name: "generic_username_-_account_key-value",
			input: `
				account=login123
				token=gldt-k3tx_ycYvssk_8FLUHju
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Token: "gldt-k3tx_ycYvssk_8FLUHju",
				},
			},
		},
		{
			name: "username_with_quotes",
			input: `
				username="quoted_user"
				token=gldt-W6xaS96Cxzb87K5XsdAh
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Token: "gldt-W6xaS96Cxzb87K5XsdAh",
				},
			},
		},
		{
			name: "username_with_single_quotes",
			input: `
				username='single_quoted'
				token=gldt-z6bNg4ZFGTAxf3GSpdiBgitlab
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Token: "gldt-z6bNg4ZFGTAxf3GSpdiBgitlab",
				},
			},
		},
		{
			name: "invalid_-_token_too_short",
			input: `
				gitlab+deploy-token-12345
				gldt-short
			`,
			want: nil,
		},
		{
			name: "invalid -_wrong_username_format_-_returns_token_only",
			input: `
				randomtext123
				gldt-W6xaS96Cxzb87K5XsdAh
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{Token: "gldt-W6xaS96Cxzb87K5XsdAh"},
			},
		},
		{
			name: "invalid_-_wrong_token_prefix",
			input: `
				gitlab+deploy-token-12345
				glcbt-W6xaS96Cxzb87K5XsdAh
			`,
			want: nil,
		},
		{
			name: "multiple_tokens_-_should_detect_all",
			input: `
				https://gitlab.com/group1/project1.git
				gitlab+deploy-token-11111
				gldt-FirstToken123456789
				
				https://gitlab.com/group2/project2.git
				gitlab+deploy-token-22222
				gldt-SecondToken12345678
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Token:    "gldt-FirstToken123456789",
					Username: "gitlab+deploy-token-11111",
					RepoURL:  "https://gitlab.com/group1/project1.git",
				},
				gitlabdeploytoken.GitlabDeployToken{
					Token:    "gldt-SecondToken12345678",
					Username: "gitlab+deploy-token-22222",
					RepoURL:  "https://gitlab.com/group2/project2.git",
				},
			},
		},
		{
			name: "token_at_minimum_length_(15_chars_after_prefix)",
			input: `
				https://gitlab.com/test/repo.git
				username: myusername
				gldt-123456789abcdef
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Token:    "gldt-123456789abcdef",
					Username: "username: myusername",
					RepoURL:  "https://gitlab.com/test/repo.git",
				},
			},
		},
		{
			name: "token_with_mixed_case_and_underscores",
			input: `
				https://gitlab.com/test/repo.git
				user: myusername
				gldt-AbC_DeF_123_XyZ_456
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Token:    "gldt-AbC_DeF_123_XyZ_456",
					Username: "user: myusername",
					RepoURL:  "https://gitlab.com/test/repo.git",
				},
			},
		},
		{
			name: "closest_URL_is_selected_when_multiple_URLs_present",
			input: `
				https://gitlab.com/far/away.git
				
				username=testusername
				gldt-TokenShouldMatchClosest
				https://gitlab.com/close/repo.git
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Token:    "gldt-TokenShouldMatchClosest",
					Username: "username=testusername",
					RepoURL:  "https://gitlab.com/close/repo.git",
				},
			},
		},
		{
			name: "SSH_URL-style_format",
			input: `
				ssh://git@gitlab.com/mygroup/myproject.git
				username: gitlab+deploy-token-12345
				gldt-SSHUrlStyleToken123
			`,
			want: []veles.Secret{
				gitlabdeploytoken.GitlabDeployToken{
					Token:    "gldt-SSHUrlStyleToken123",
					Username: "username: gitlab+deploy-token-12345",
					RepoURL:  "ssh://git@gitlab.com/mygroup/myproject.git",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := gitlabdeploytoken.NewDetector()
			got, _ := detector.Detect([]byte(tt.input))
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Detect() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
