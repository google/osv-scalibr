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

package gcpoauth2client_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gcpoauth2client"
)

func TestDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []veles.Secret
	}{
		{
			name:     "no secrets",
			input:    "This is just some random text with no credentials",
			expected: nil,
		},
		{
			name: "simple file with one client ID and secret - close proximity",
			input: `123456789012-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com
GOCSPX-1mVwFTjGIXgs2BC2uHzksQi0HAK`,
			expected: []veles.Secret{
				gcpoauth2client.ClientCredentials{
					ClientID:     "123456789012-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-1mVwFTjGIXgs2BC2uHzksQi0HAK",
				},
			},
		},
		{
			name: "simple file with one client ID and secret - JSON format",
			input: `{
				"client_id": "717762328687-iludtf96g1hinl76e4lc1b9a82g457nn.apps.googleusercontent.com",
				"client_secret": "GOCSPX-WebAppSecret9876543210ABC"
			}`,
			expected: []veles.Secret{
				gcpoauth2client.ClientCredentials{
					ClientID:     "717762328687-iludtf96g1hinl76e4lc1b9a82g457nn.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-WebAppSecret9876543210ABC",
				},
			},
		},
		{
			name: "complex file with multiple client ID and secret - test proximity",
			input: `config_app1:
111111111111-first.apps.googleusercontent.com
GOCSPX-FirstSecret123456789012

config_app2:
222222222222-second.apps.googleusercontent.com
GOCSPX-SecondSecret987654321098`,
			expected: []veles.Secret{
				gcpoauth2client.ClientCredentials{
					ClientID:     "222222222222-second.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-FirstSecret123456789012",
				},
				gcpoauth2client.ClientCredentials{
					ClientID:     "111111111111-first.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-SecondSecret987654321098",
				},
			},
		},
		{
			name: "complex file with multiple client ID and secret - far apart (no pairing)",
			input: `config_app1:
111111111111-first.apps.googleusercontent.com` + strings.Repeat("\nfiller line with random data", 500) + `
config_app2:
GOCSPX-FarAwaySecret123456789012`,
			expected: []veles.Secret{
				gcpoauth2client.ClientCredentials{
					ClientID: "111111111111-first.apps.googleusercontent.com",
				},
				gcpoauth2client.ClientCredentials{
					ClientSecret: "GOCSPX-FarAwaySecret123456789012",
				},
			},
		},
		{
			name:  "client ID but no client secret",
			input: `app_id: 333333333333-standalone.apps.googleusercontent.com`,
			expected: []veles.Secret{
				gcpoauth2client.ClientCredentials{
					ClientID: "333333333333-standalone.apps.googleusercontent.com",
				},
			},
		},
		{
			name:  "client secret but no client ID",
			input: `app_secret: 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`,
			expected: []veles.Secret{
				gcpoauth2client.ClientCredentials{
					ClientSecret: "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",
				},
			},
		},
		{
			name: "multiple client IDs with one secret - closest pairing",
			input: `first_id: 111111111111-first.apps.googleusercontent.com
second_id: 222222222222-second.apps.googleusercontent.com
shared_secret: GOCSPX-SharedSecret123456789012`,
			expected: []veles.Secret{
				gcpoauth2client.ClientCredentials{
					ClientID:     "222222222222-second.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-SharedSecret123456789012",
				},
				gcpoauth2client.ClientCredentials{
					ClientID: "111111111111-first.apps.googleusercontent.com",
				},
			},
		},
		{
			name: "one client ID with multiple secrets - closest pairing",
			input: `first_secret: GOCSPX-FirstSecret123456789012
shared_id: 333333333333-shared.apps.googleusercontent.com
second_secret: GOCSPX-SecondSecret987654321098`,
			expected: []veles.Secret{
				gcpoauth2client.ClientCredentials{
					ClientID:     "333333333333-shared.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-FirstSecret123456789012",
				},
				gcpoauth2client.ClientCredentials{
					ClientSecret: "GOCSPX-SecondSecret987654321098",
				},
			},
		},
		{
			name:     "invalid client ID format - too short prefix",
			input:    "123456789-tooshort.apps.googleusercontent.com",
			expected: nil,
		},
		{
			name:     "invalid client ID format - wrong domain",
			input:    "123456789012-valid.example.com",
			expected: nil,
		},
		{
			name:     "invalid client secret format - wrong prefix",
			input:    "WRONG-1mVwFTjGIXgs2BC2uHzksQi0HAK",
			expected: nil,
		},
		{
			name:     "invalid client secret format - too short",
			input:    "GOCSPX-short",
			expected: nil,
		},
		{
			name: "valid formats mixed with invalid",
			input: `valid_id: 444444444444-valid.apps.googleusercontent.com
invalid_id: 123-invalid.apps.googleusercontent.com
valid_secret: GOCSPX-ValidSecret123456789012
invalid_secret: WRONG-InvalidSecret123456789012`,
			expected: []veles.Secret{
				gcpoauth2client.ClientCredentials{
					ClientID:     "444444444444-valid.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-ValidSecret123456789012",
				},
			},
		},
		{
			name: "real world client_secrets.json example",
			input: `{
  "web": {
    "client_id": "555666777888-webappclient.apps.googleusercontent.com",
    "project_id": "my-project-123",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_secret": "GOCSPX-RealWorldExample123456789",
    "redirect_uris": ["http://localhost:8080/callback"]
  }
}`,
			expected: []veles.Secret{
				gcpoauth2client.ClientCredentials{
					ClientID:     "555666777888-webappclient.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-RealWorldExample123456789",
				},
			},
		},
		{
			name: "deduplication test - same client ID appears multiple times",
			input: `first_occurrence: 123456789012-duplicate.apps.googleusercontent.com
some_other_data: random_value
second_occurrence: 123456789012-duplicate.apps.googleusercontent.com
secret: GOCSPX-DuplicateTest123456789012`,
			expected: []veles.Secret{
				gcpoauth2client.ClientCredentials{
					ClientID:     "123456789012-duplicate.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-DuplicateTest123456789012",
				},
				gcpoauth2client.ClientCredentials{
					ClientID: "123456789012-duplicate.apps.googleusercontent.com",
				},
			},
		},
		{
			name: "deduplication test - same client secret appears multiple times",
			input: `id: 111111111111-unique.apps.googleusercontent.com
first_secret: GOCSPX-DuplicateSecret123456789
some_other_data: random_value
second_secret: GOCSPX-DuplicateSecret123456789`,
			expected: []veles.Secret{
				gcpoauth2client.ClientCredentials{
					ClientID:     "111111111111-unique.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-DuplicateSecret123456789",
				},
				gcpoauth2client.ClientCredentials{
					ClientSecret: "GOCSPX-DuplicateSecret123456789",
				},
			},
		},
		{
			name: "deduplication test - multiple pairs with overlapping credentials",
			input: `shared_id: 123456789012-shared.apps.googleusercontent.com
first_secret: GOCSPX-FirstSecret123456789012
another_id: 987654321098-another.apps.googleusercontent.com
shared_secret: GOCSPX-SharedSecret987654321098
shared_id_again: 123456789012-shared.apps.googleusercontent.com
shared_secret_again: GOCSPX-SharedSecret987654321098`,
			expected: []veles.Secret{
				gcpoauth2client.ClientCredentials{
					ClientID:     "987654321098-another.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-FirstSecret123456789012",
				},
				gcpoauth2client.ClientCredentials{
					ClientID:     "123456789012-shared.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-SharedSecret987654321098",
				},
				gcpoauth2client.ClientCredentials{
					ClientID:     "123456789012-shared.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-SharedSecret987654321098",
				},
			},
		},
		{
			name: "deduplication test - ensures no double pairing of same credentials",
			input: `first_id: 111111111111-first.apps.googleusercontent.com
unique_secret: GOCSPX-UniqueSecret123456789012
second_id: 222222222222-second.apps.googleusercontent.com
first_id_again: 111111111111-first.apps.googleusercontent.com`,
			expected: []veles.Secret{
				gcpoauth2client.ClientCredentials{
					ClientID:     "222222222222-second.apps.googleusercontent.com",
					ClientSecret: "GOCSPX-UniqueSecret123456789012",
				},
				gcpoauth2client.ClientCredentials{
					ClientID: "111111111111-first.apps.googleusercontent.com",
				},
				gcpoauth2client.ClientCredentials{
					ClientID: "111111111111-first.apps.googleusercontent.com",
				},
			},
		},
	}

	detector := gcpoauth2client.NewDetector()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets, _ := detector.Detect([]byte(tt.input))

			if diff := cmp.Diff(tt.expected, secrets); diff != "" {
				t.Errorf("Detect() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetector_MaxSecretLen(t *testing.T) {
	detector := gcpoauth2client.NewDetector()
	maxLen := detector.MaxSecretLen()
	if maxLen != 10240 {
		t.Errorf("MaxSecretLen() = %d, want 10240", maxLen)
	}
}
