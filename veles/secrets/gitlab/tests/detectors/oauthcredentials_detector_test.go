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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gitlab"
)

func TestOAuthCredentialsDetector_FindSecrets(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name: "valid_oauth_credentials_with_all_fields",
			input: `
				client_id: 9bedc237a4666df945257eb69a20ed9e53b64166fe9abb3f79c9f7ba42c4355f
				client_secret: gloas-cff41fbbd4212f7dfe05907bfb8a494f44b31e5966722a3563149946817f76c0
				https://gitlab.com
			`,
			want: []veles.Secret{
				gitlab.OAuthCredentials{
					ClientID:     "9bedc237a4666df945257eb69a20ed9e53b64166fe9abb3f79c9f7ba42c4355f",
					ClientSecret: "gloas-cff41fbbd4212f7dfe05907bfb8a494f44b31e5966722a3563149946817f76c0",
					Hostname:     "https://gitlab.com",
				},
			},
		},
		{
			name: "valid_oauth_credentials_with_self_hosted_instance",
			input: `
				client_id=1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
				client_secret=gloas-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
				https://gitlab.example.com
			`,
			want: []veles.Secret{
				gitlab.OAuthCredentials{
					ClientID:     "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
					ClientSecret: "gloas-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
					Hostname:     "https://gitlab.example.com",
				},
			},
		},
		{
			name: "valid_oauth_credentials_without_hostname",
			input: `
				client_id: abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
				client_secret: gloas-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
			`,
			want: []veles.Secret{
				gitlab.OAuthCredentials{
					ClientSecret: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				},
				gitlab.OAuthCredentials{
					ClientSecret: "gloas-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				},
			},
		},
		{
			name: "partial_match_client_secret_only",
			input: `
				some random text
				gloas-fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
				more text
			`,
			want: []veles.Secret{
				gitlab.OAuthCredentials{
					ClientSecret: "gloas-fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
				},
			},
		},
		{
			name: "oauth_credentials_with_port_in_hostname",
			input: `
				client_id: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
				client_secret: gloas-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
				https://gitlab.example.com:8443
			`,
			want: []veles.Secret{
				gitlab.OAuthCredentials{
					ClientID:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					ClientSecret: "gloas-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					Hostname:     "https://gitlab.example.com:8443",
				},
			},
		},
		{
			name: "oauth_credentials_with_http_protocol",
			input: `
				client-id="9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef"
				client-secret="gloas-9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef"
				http://localhost:8080
			`,
			want: []veles.Secret{
				gitlab.OAuthCredentials{
					ClientID:     "9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef",
					ClientSecret: "gloas-9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef",
					Hostname:     "http://localhost:8080",
				},
			},
		},
		{
			name: "invalid_client_secret_wrong_prefix",
			input: `
				client_id: 9bedc237a4666df945257eb69a20ed9e53b64166fe9abb3f79c9f7ba42c4355f
				client_secret: glpat-cff41fbbd4212f7dfe05907bfb8a494f44b31e5966722a3563149946817f76c0
			`,
			want: []veles.Secret{
				gitlab.OAuthCredentials{
					ClientSecret: "9bedc237a4666df945257eb69a20ed9e53b64166fe9abb3f79c9f7ba42c4355f",
				},
				gitlab.OAuthCredentials{
					ClientSecret: "cff41fbbd4212f7dfe05907bfb8a494f44b31e5966722a3563149946817f76c0",
				},
			},
		},
		{
			name: "invalid_client_secret_wrong_length",
			input: `
				client_id: 9bedc237a4666df945257eb69a20ed9e53b64166fe9abb3f79c9f7ba42c4355f
				client_secret: gloas-cff41fbbd4212f7dfe05907bfb8a494f44b31e5966722a3563149946817f
			`,
			want: []veles.Secret{
				gitlab.OAuthCredentials{
					ClientSecret: "9bedc237a4666df945257eb69a20ed9e53b64166fe9abb3f79c9f7ba42c4355f",
				},
			},
		},
		{
			name: "invalid_client_id_wrong_length",
			input: `
				client_id: 9bedc237a4666df945257eb69a20ed9e53b64166fe9abb3f79c9f7ba42c43
				client_secret: gloas-cff41fbbd4212f7dfe05907bfb8a494f44b31e5966722a3563149946817f76c0
			`,
			want: []veles.Secret{
				gitlab.OAuthCredentials{
					ClientSecret: "gloas-cff41fbbd4212f7dfe05907bfb8a494f44b31e5966722a3563149946817f76c0",
				},
			},
		},
		{
			name: "invalid_client_secret_non_hex_characters",
			input: `
				client_id: 9bedc237a4666df945257eb69a20ed9e53b64166fe9abb3f79c9f7ba42c4355f
				client_secret: gloas-cff41fbbd4212f7dfe05907bfb8a494f44b31e5966722a3563149946817f76cZ
			`,
			want: []veles.Secret{
				gitlab.OAuthCredentials{
					ClientSecret: "9bedc237a4666df945257eb69a20ed9e53b64166fe9abb3f79c9f7ba42c4355f",
				},
			},
		},
		{
			name: "no_secrets_in_plain_text",
			input: `
				This is just some random text without any secrets.
				Nothing to see here.
			`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := gitlab.NewOAuthCredentialsDetector()
			got, _ := detector.Detect([]byte(tt.input))

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Detect() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
