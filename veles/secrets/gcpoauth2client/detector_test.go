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
			name: "client_ID_and_secret_in_close_proximity",
			input: `123456789012-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com
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`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "123456789012-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com",
					Secret: "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",
				},
			},
		},
		{
			name: "client_secret_in_with_invalid_prefix",
			input: `123456789012-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com
abcGOCSPX-1mVwFTjGIXgs2BC2uHzksQi0HAK1`,
			want: nil,
		},
		{
			name: "client_ID_and_secret_in_close_proximity_in_json_format",
			input: `{
				"client_id": "717762328687-iludtf96g1hinl76e4lc1b9a82g457nn.apps.googleusercontent.com",
				"client_secret": "GOCSPX-WebAppSecret9876543210ABCDEF"
			}`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "717762328687-iludtf96g1hinl76e4lc1b9a82g457nn.apps.googleusercontent.com",
					Secret: "GOCSPX-WebAppSecret9876543210ABCDEF",
				},
			},
		},
		{
			name: "valid_formats_mixed_with_invalid",
			input: `valid_id: 444444444444-valid.apps.googleusercontent.com
invalid_id: 123-invalid.apps.googleusercontent.com
valid_secret: GOCSPX-ValidSecret12345678901234567
invalid_secret: WRONG-InvalidSecret123456789012345`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "444444444444-valid.apps.googleusercontent.com",
					Secret: "GOCSPX-ValidSecret12345678901234567",
				},
			},
		},
		// -- Multiple Client ID and Secret in close proximity ---
		{
			name: "complex_file_with_multiple_client_ID_and_secret_-_test_proximity",
			input: `config_app1:
111111111111-first.apps.googleusercontent.com
GOCSPX-FirstSecret12345678901234567

config_app2:
222222222222-second.apps.googleusercontent.com
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`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "111111111111-first.apps.googleusercontent.com",
					Secret: "GOCSPX-FirstSecret12345678901234567",
				},
				gcpoauth2client.Credentials{
					ID:     "222222222222-second.apps.googleusercontent.com",
					Secret: "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",
				},
			},
		},
		{
			name: "real_world_client_secrets.json_example",
			input: `{
  "web": {
    "client_id": "555666777888-webappclient.apps.googleusercontent.com",
    "project_id": "my-project-123",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_secret": "GOCSPX-RealWorldExample123456789012",
    "redirect_uris": ["http://localhost:8080/callback"]
  }
}`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "555666777888-webappclient.apps.googleusercontent.com",
					Secret: "GOCSPX-RealWorldExample123456789012",
				},
			},
		},
		// -- Multiple Client ID and Secret in with varied proximity ---
		{
			name: "complex_file_with_multiple_client_ID_and_secret_-_far_apart_(no_pairing)",
			input: `config_app1:
111111111111-first.apps.googleusercontent.com` + strings.Repeat("\nfiller line with random data", 500) + `
config_app2:
GOCSPX-FarAwaySecret123456789012345`,
			want: nil,
		},
		{
			name: "multiple_client_IDs_with_one_secret_-_closest_pairing",
			input: `first_id: 111111111111-first.apps.googleusercontent.com
second_id: 222222222222-second.apps.googleusercontent.com
shared_secret: GOCSPX-SharedSecret1234567890123456`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "222222222222-second.apps.googleusercontent.com",
					Secret: "GOCSPX-SharedSecret1234567890123456",
				},
			},
		},
		{
			name: "one_client_ID_with_multiple_secrets_-_closest_pairing",
			input: `first_secret: GOCSPX-FirstSecret12345678901234567
shared_id: 333333333333-shared.apps.googleusercontent.com
second_secret: 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`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "333333333333-shared.apps.googleusercontent.com",
					Secret: "GOCSPX-FirstSecret12345678901234567",
				},
			},
		},
		// --- Duplicate client ID or secret ---
		{
			name: "deduplication_test_-_same_client_ID_appears_multiple_times",
			input: `first_occurrence: 123456789012-duplicate.apps.googleusercontent.com
some_other_data: random_value
second_occurrence: 123456789012-duplicate.apps.googleusercontent.com
secret: GOCSPX-DuplicateTest123456789012345`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "123456789012-duplicate.apps.googleusercontent.com",
					Secret: "GOCSPX-DuplicateTest123456789012345",
				},
			},
		},
		{
			name: "deduplication_test_-_same_client_secret_appears_multiple_times",
			input: `id: 111111111111-unique.apps.googleusercontent.com
first_secret: GOCSPX-DuplicateSecret1234567890123
some_other_data: random_value
second_secret: GOCSPX-DuplicateSecret1234567890123`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "111111111111-unique.apps.googleusercontent.com",
					Secret: "GOCSPX-DuplicateSecret1234567890123",
				},
			},
		},
		{
			name: "deduplication_test_-_multiple_pairs_with_overlapping_credentials",
			input: `shared_id: 123456789012-shared.apps.googleusercontent.com
first_secret: GOCSPX-FirstSecret12345678901234567
another_id: 987654321098-another.apps.googleusercontent.com
shared_secret: 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
shared_id_again: 123456789012-shared.apps.googleusercontent.com
shared_secret_again: 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`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "987654321098-another.apps.googleusercontent.com",
					Secret: "GOCSPX-FirstSecret12345678901234567",
				},
				gcpoauth2client.Credentials{
					ID:     "123456789012-shared.apps.googleusercontent.com",
					Secret: "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",
				},
				gcpoauth2client.Credentials{
					ID:     "123456789012-shared.apps.googleusercontent.com",
					Secret: "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",
				},
			},
		},
		{
			name: "deduplication_test_-_ensures_no_double_pairing_of_same_credentials",
			input: `first_id: 111111111111-first.apps.googleusercontent.com
unique_secret: GOCSPX-UniqueSecret1234567890123456
second_id: 222222222222-second.apps.googleusercontent.com
first_id_again: 111111111111-first.apps.googleusercontent.com`,
			want: []veles.Secret{
				gcpoauth2client.Credentials{
					ID:     "222222222222-second.apps.googleusercontent.com",
					Secret: "GOCSPX-UniqueSecret1234567890123456",
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
