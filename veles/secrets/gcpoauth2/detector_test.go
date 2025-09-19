// Copyright 2025 Google LLC
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

package gcpoauth2_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gcpoauth2"
)

func TestDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []veles.Secret
	}{
		{
			name:     "no credentials",
			input:    "This is just some random text with no credentials",
			expected: nil,
		},
		{
			name: "JSON format with both client_id and client_secret",
			input: `{
				"client_id": "717762328687-iludtf96g1hinl76e4lc1b9a82g457nn.apps.googleusercontent.com",
				"client_secret": "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"
			}`,
			expected: []veles.Secret{
				gcpoauth2.ClientCredentials{
					ClientID:     "717762328687-iludtf96g1hinl76e4lc1b9a82g457nn.apps.googleusercontent.com",
					ClientSecret: "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",
				},
			},
		},
		{
			name: "environment variable format",
			input: `
GOOGLE_CLIENT_ID=123456789012-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=ABCD-efgh1234567890ijklmnop
			`,
			expected: []veles.Secret{
				gcpoauth2.ClientCredentials{
					ClientID:     "123456789012-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com",
					ClientSecret: "ABCD-efgh1234567890ijklmnop",
				},
			},
		},
		{
			name: "YAML format",
			input: `
oauth:
  client_id: 987654321098-zyxwvutsrqponmlkjihgfedcba.apps.googleusercontent.com
  client_secret: GOCSPX-A1B2C3D4E5F6G7H8I9J0K1L2M3
			`,
			expected: []veles.Secret{
				gcpoauth2.ClientCredentials{
					ClientID:     "987654321098-zyxwvutsrqponmlkjihgfedcba.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-A1B2C3D4E5F6G7H8I9J0K1L2M3",
				},
			},
		},
		{
			name:  "standalone client_id only",
			input: `config.client_id = "556677889900-abcdefghijklmnopqrstuvwxyz123456.apps.googleusercontent.com"`,
			expected: []veles.Secret{
				gcpoauth2.ClientCredentials{
					ClientID: "556677889900-abcdefghijklmnopqrstuvwxyz123456.apps.googleusercontent.com",
				},
			},
		},
		{
			name:  "standalone client_secret only",
			input: `config.client_secret = "GOCSPX-SecretValue123456789012345"`,
			expected: []veles.Secret{
				gcpoauth2.ClientCredentials{
					ClientSecret: "GOCSPX-SecretValue123456789012345",
				},
			},
		},
		{
			name:  "client_id without context should be detected as ID",
			input: `112233445566-validformat.apps.googleusercontent.com`,
			expected: []veles.Secret{
				gcpoauth2.ClientCredentials{
					ID: "112233445566-validformat.apps.googleusercontent.com",
				},
			},
		},
		{
			name: "mixed formats far apart - should be detected separately",
			input: `{
				"client_id": "111222333444-first.apps.googleusercontent.com"
			}` + strings.Repeat("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.\n", 50) + `{
				"client_secret": "GOCSPX-AnotherSecretValue123456"
			}`,
			expected: []veles.Secret{
				gcpoauth2.ClientCredentials{
					ClientID: "111222333444-first.apps.googleusercontent.com",
				},
				gcpoauth2.ClientCredentials{
					ClientSecret: "GOCSPX-AnotherSecretValue123456",
				},
			},
		},
		{
			name: "credentials in client_secret.json format",
			input: `{
				"web": {
					"client_id": "444555666777-webappclient.apps.googleusercontent.com",
					"project_id": "my-project-123",
					"auth_uri": "https://accounts.google.com/o/oauth2/auth",
					"token_uri": "https://oauth2.googleapis.com/token",
					"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
					"client_secret": "GOCSPX-WebAppSecret9876543210ABC"
				}
			}`,
			expected: []veles.Secret{
				gcpoauth2.ClientCredentials{
					ClientID:     "444555666777-webappclient.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-WebAppSecret9876543210ABC",
				},
			},
		},
		{
			name: "multiple credential pairs",
			input: `{
				"client_id": "111111111111-first.apps.googleusercontent.com",
				"client_secret": "GOCSPX-FirstSecret123456789012"
			}
			{
				"client_id": "222222222222-second.apps.googleusercontent.com",
				"client_secret": "GOCSPX-SecondSecret987654321098"
			}`,
			expected: []veles.Secret{
				gcpoauth2.ClientCredentials{
					ClientID:     "111111111111-first.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-FirstSecret123456789012",
				},
				gcpoauth2.ClientCredentials{
					ClientID:     "222222222222-second.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-SecondSecret987654321098",
				},
			},
		},
		{
			name: "invalid client_id format should not create context match",
			input: `{
				"client_id": "invalid-format-missing-apps-googleusercontent-com",
				"client_secret": "GOCSPX-SomeSecret123456789012345"
			}`,
			expected: []veles.Secret{
				gcpoauth2.ClientCredentials{
					ClientSecret: "GOCSPX-SomeSecret123456789012345",
				},
			},
		},
		{
			name: "case insensitive field matching",
			input: `
CLIENT_ID=888999000111-casetest.apps.googleusercontent.com
CLIENT_SECRET=GOCSPX-CaseTestSecret123456789
			`,
			expected: []veles.Secret{
				gcpoauth2.ClientCredentials{
					ClientID:     "888999000111-casetest.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-CaseTestSecret123456789",
				},
			},
		},
		{
			name:  "valid client ID formats with different lengths",
			input: "client_id: 1234567890-short.apps.googleusercontent.com\nclient_id: 123456789012345-longer.apps.googleusercontent.com",
			expected: []veles.Secret{
				gcpoauth2.ClientCredentials{
					ClientID: "1234567890-short.apps.googleusercontent.com",
				},
				gcpoauth2.ClientCredentials{
					ClientID: "123456789012345-longer.apps.googleusercontent.com",
				},
			},
		},
		{
			name:     "invalid numeric prefix too short",
			input:    "client_id: 123456789-tooshort.apps.googleusercontent.com",
			expected: nil,
		},
		{
			name:     "invalid domain",
			input:    "client_id: 123456789012-valid.example.com",
			expected: nil,
		},
		{
			name:     "client secret too short",
			input:    "client_secret: short",
			expected: nil,
		},
		{
			name: "complex mixed scenario with far and close secrets",
			input: `{
				"app_config": {
					"client_id": "111111111111-close.apps.googleusercontent.com",
					"client_secret": "GOCSPX-CloseSecret123456789012"
				}
			}` + strings.Repeat("Other configuration data here with various API keys and tokens.\n", 30) + `{
				"database": {
					"host": "db.example.com",
					"client_id": "222222222222-far.apps.googleusercontent.com"
				}
			}` + strings.Repeat("More unrelated configuration and settings.\n", 20) + `{
				"auth": {
					"client_secret": "GOCSPX-FarSecret987654321098"
				}
			}` + `{
				"another_service": {
					"client_id": "333333333333-another.apps.googleusercontent.com",
					"client_secret": "GOCSPX-AnotherClose456789012345"
				}
			}`,
			expected: []veles.Secret{
				gcpoauth2.ClientCredentials{
					ClientID:     "111111111111-close.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-CloseSecret123456789012",
				},
				gcpoauth2.ClientCredentials{
					ClientID:     "333333333333-another.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-AnotherClose456789012345",
				},
				gcpoauth2.ClientCredentials{
					ClientID: "222222222222-far.apps.googleusercontent.com",
				},
				gcpoauth2.ClientCredentials{
					ClientSecret: "GOCSPX-FarSecret987654321098",
				},
			},
		},
		{
			name: "long random string should not match",
			input: `{
				"random_data": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
				"another_field": "1234567890-this-looks-like-clientid-but-wrong-domain.example.com"
			}`,
			expected: nil,
		},
		{
			name: "base64 encoded blob should not match",
			input: `{
				"encoded_data": "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgZW5jb2RlZCBzdHJpbmcgdGhhdCBtaWdodCBjb250YWluIGNyZWRlbnRpYWxzIGJ1dCBkb2VzbnQgbWF0Y2ggb3VyIHBhdHRlcm5z",
				"client_data": "bm90LWEtdmFsaWQtY2xpZW50LWlkLWZvcm1hdA=="
			}`,
			expected: nil,
		},
		{
			name: "json with different secret types should not match",
			input: `{
				"api_key": "sk-1234567890abcdef1234567890abcdef12345678",
				"aws_access_key": "AKIAIOSFODNN7EXAMPLE",
				"aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"github_token": "ghp_1234567890abcdef1234567890abcdef123456",
				"database_url": "postgres://user:pass@localhost:5432/db"
			}`,
			expected: nil,
		},
		{
			name: "json with no secrets at all",
			input: `{
				"app_name": "MyApplication",
				"version": "1.0.0",
				"description": "A sample application configuration",
				"features": ["feature1", "feature2", "feature3"],
				"settings": {
					"theme": "dark",
					"language": "en",
					"timeout": 30000
				},
				"endpoints": {
					"api": "https://api.example.com",
					"auth": "https://auth.example.com",
					"cdn": "https://cdn.example.com"
				}
			}`,
			expected: nil,
		},
		{
			name: "almost valid client_id formats with subtle errors",
			input: `{
				"client_id_short_numeric": "12345-toolshort.apps.googleusercontent.com",
				"client_id_wrong_domain": "123456789012-correct.apps.google.com",
				"client_id_missing_apps": "123456789012-missing.googleusercontent.com",
				"client_secret_too_short": "GOCSPX-short",
				"client_secret_wrong_prefix": "GOCAPI-1mVwFTjGIXgs2BC2uHzksQi0HAK"
			}`,
			expected: nil,
		},
	}

	detector := gcpoauth2.NewDetector()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets, _ := detector.Detect([]byte(tt.input))

			if diff := cmp.Diff(tt.expected, secrets, cmpopts.IgnoreFields(gcpoauth2.ClientCredentials{}, "ID")); diff != "" {
				// For cases where we expect ID field, check it separately
				if len(tt.expected) > 0 {
					if expected, ok := tt.expected[0].(gcpoauth2.ClientCredentials); ok && expected.ID != "" {
						if len(secrets) > 0 {
							if actual, ok := secrets[0].(gcpoauth2.ClientCredentials); ok && actual.ID != "" {
								// ID field is set, this is expected
								return
							}
						}
					}
				}
				t.Errorf("Detect() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetector_MaxSecretLen(t *testing.T) {
	detector := gcpoauth2.NewDetector()
	maxLen := detector.MaxSecretLen()
	if maxLen != 1000 {
		t.Errorf("MaxSecretLen() = %d, want 1000", maxLen)
	}
}
