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
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gcpoauth2client"
)

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{gcpoauth2client.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		// --- Empty or invalid input ---
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
		{
			name:  "non-credential input",
			input: "Some random text",
			want:  nil,
		},
		{
			name:  "invalid client ID format - too short prefix",
			input: "123456789-tooshort.apps.googleusercontent.com",
			want:  nil,
		},
		{
			name:  "invalid client ID format - wrong domain",
			input: "123456789012-valid.example.com",
			want:  nil,
		},
		{
			name:  "invalid client secret format - wrong prefix",
			input: "WRONG-1mVwFTjGIXgs2BC2uHzksQi0HAK",
			want:  nil,
		},
		{
			name:  "invalid client secret format - too short",
			input: "GOCSPX-short",
			want:  nil,
		},
		// --- Only client ID or Secret ---
		{
			name:  "client ID but no client secret",
			input: `app_id: 333333333333-standalone.apps.googleusercontent.com`,
			want:  nil,
		},
		{
			name:  "client secret but no client ID",
			input: `app_secret: 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`,
			want:  nil,
		},
		// -- Single Client ID and Secret in close proximity (happy path) ---
		{
			name: "client ID and secret in close proximity",
			input: `123456789012-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com
GOCSPX-1mVwFTjGIXgs2BC2uHzksQi0HAK`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "123456789012-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com",
					Secret: "GOCSPX-1mVwFTjGIXgs2BC2uHzksQi0HAK",
				},
			},
		},
		{
			name: "client secret in with invalid prefix",
			input: `123456789012-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com
abcGOCSPX-1mVwFTjGIXgs2BC2uHzksQi0HAK`,
			want: nil,
		},
		{
			name: "client ID and secret in close proximity in json format",
			input: `{
				"client_id": "717762328687-iludtf96g1hinl76e4lc1b9a82g457nn.apps.googleusercontent.com",
				"client_secret": "GOCSPX-WebAppSecret9876543210ABC"
			}`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "717762328687-iludtf96g1hinl76e4lc1b9a82g457nn.apps.googleusercontent.com",
					Secret: "GOCSPX-WebAppSecret9876543210ABC",
				},
			},
		},
		{
			name: "valid formats mixed with invalid",
			input: `valid_id: 444444444444-valid.apps.googleusercontent.com
invalid_id: 123-invalid.apps.googleusercontent.com
valid_secret: GOCSPX-ValidSecret123456789012
invalid_secret: WRONG-InvalidSecret123456789012`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "444444444444-valid.apps.googleusercontent.com",
					Secret: "GOCSPX-ValidSecret123456789012",
				},
			},
		},
		// -- Multiple Client ID and Secret in close proximity ---
		{
			name: "complex file with multiple client ID and secret - test proximity",
			input: `config_app1:
111111111111-first.apps.googleusercontent.com
GOCSPX-FirstSecret123456789012

config_app2:
222222222222-second.apps.googleusercontent.com
GOCSPX-SecondSecret987654321098`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "222222222222-second.apps.googleusercontent.com",
					Secret: "GOCSPX-FirstSecret123456789012",
				},
				gcpoauth2client.Credentials{
					ID:     "111111111111-first.apps.googleusercontent.com",
					Secret: "GOCSPX-SecondSecret987654321098",
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
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "555666777888-webappclient.apps.googleusercontent.com",
					Secret: "GOCSPX-RealWorldExample123456789",
				},
			},
		},
		{
			name: "multiple client IDs with one secret - closest pairing",
			input: `first_id: 111111111111-first.apps.googleusercontent.com
second_id: 222222222222-second.apps.googleusercontent.com
shared_secret: GOCSPX-SharedSecret123456789012`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "222222222222-second.apps.googleusercontent.com",
					Secret: "GOCSPX-SharedSecret123456789012",
				},
			},
		},
		{
			name: "one client ID with multiple secrets - closest pairing",
			input: `first_secret: GOCSPX-FirstSecret123456789012
shared_id: 333333333333-shared.apps.googleusercontent.com
second_secret: GOCSPX-SecondSecret987654321098`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "333333333333-shared.apps.googleusercontent.com",
					Secret: "GOCSPX-FirstSecret123456789012",
				},
			},
		},
		// --- Duplicate client ID or secret ---
		{
			name: "deduplication test - same client ID appears multiple times",
			input: `first_occurrence: 123456789012-duplicate.apps.googleusercontent.com
some_other_data: random_value
second_occurrence: 123456789012-duplicate.apps.googleusercontent.com
secret: GOCSPX-DuplicateTest123456789012`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "123456789012-duplicate.apps.googleusercontent.com",
					Secret: "GOCSPX-DuplicateTest123456789012",
				},
			},
		},
		{
			name: "deduplication test - same client secret appears multiple times",
			input: `id: 111111111111-unique.apps.googleusercontent.com
first_secret: GOCSPX-DuplicateSecret123456789
some_other_data: random_value
second_secret: GOCSPX-DuplicateSecret123456789`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "111111111111-unique.apps.googleusercontent.com",
					Secret: "GOCSPX-DuplicateSecret123456789",
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
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "987654321098-another.apps.googleusercontent.com",
					Secret: "GOCSPX-FirstSecret123456789012",
				},
				gcpoauth2client.Credentials{
					ID:     "123456789012-shared.apps.googleusercontent.com",
					Secret: "GOCSPX-SharedSecret987654321098",
				},
				gcpoauth2client.Credentials{
					ID:     "123456789012-shared.apps.googleusercontent.com",
					Secret: "GOCSPX-SharedSecret987654321098",
				},
			},
		},
		{
			name: "deduplication test - ensures no double pairing of same credentials",
			input: `first_id: 111111111111-first.apps.googleusercontent.com
unique_secret: GOCSPX-UniqueSecret123456789012
second_id: 222222222222-second.apps.googleusercontent.com
first_id_again: 111111111111-first.apps.googleusercontent.com`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "222222222222-second.apps.googleusercontent.com",
					Secret: "GOCSPX-UniqueSecret123456789012",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			fmt.Printf("got = %+v\n", got)
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
