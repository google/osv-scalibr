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

package mongodbatlasapikey_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/mongodbatlasapikey"
	"github.com/google/osv-scalibr/veles/velestest"
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		mongodbatlasapikey.NewDetector(),
		`public_api_key = "yhrqvogk"
private_api_key = "f2a79e29-8a44-4c75-a56d-5a4f7c6d1c97"`,
		mongodbatlasapikey.Credentials{PublicKey: "yhrqvogk", PrivateKey: "f2a79e29-8a44-4c75-a56d-5a4f7c6d1c97"},
	)
}

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{mongodbatlasapikey.NewDetector()})
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
			name:  "empty_input",
			input: "",
			want:  nil,
		},
		{
			name:  "no_context_keywords",
			input: "yhrqvogk f2a79e29-8a44-4c75-a56d-5a4f7c6d1c97",
			want:  nil,
		},
		// --- Only one key present ---
		{
			name:  "public_key_only",
			input: `public_api_key = "yhrqvogk"`,
			want:  nil,
		},
		{
			name:  "private_key_only",
			input: `private_api_key = "f2a79e29-8a44-4c75-a56d-5a4f7c6d1c97"`,
			want:  nil,
		},
		// --- Atlas CLI config format (TOML) ---
		{
			name: "atlas_cli_config_toml",
			input: `[default]
org_id = "5d9b0a58f10fab3a94b73abc"
public_api_key = "yhrqvogk"
private_api_key = "f2a79e29-8a44-4c75-a56d-5a4f7c6d1c97"`,
			want: []veles.Secret{
				mongodbatlasapikey.Credentials{
					PublicKey:  "yhrqvogk",
					PrivateKey: "f2a79e29-8a44-4c75-a56d-5a4f7c6d1c97",
				},
			},
		},
		// --- Environment variable format ---
		{
			name: "environment_variables",
			input: `MONGODB_ATLAS_PUBLIC_KEY=abcd1234
MONGODB_ATLAS_PRIVATE_KEY=12345678-abcd-1234-abcd-123456789abc`,
			want: []veles.Secret{
				mongodbatlasapikey.Credentials{
					PublicKey:  "abcd1234",
					PrivateKey: "12345678-abcd-1234-abcd-123456789abc",
				},
			},
		},
		// --- JSON format ---
		{
			name: "json_config",
			input: `{
  "publicApiKey": "yhrqvogk",
  "privateApiKey": "f2a79e29-8a44-4c75-a56d-5a4f7c6d1c97"
}`,
			want: []veles.Secret{
				mongodbatlasapikey.Credentials{
					PublicKey:  "yhrqvogk",
					PrivateKey: "f2a79e29-8a44-4c75-a56d-5a4f7c6d1c97",
				},
			},
		},
		// --- YAML format ---
		{
			name: "yaml_config",
			input: `mongodb_atlas:
  public_key: abcd1234
  private_key: 12345678-abcd-1234-abcd-123456789abc`,
			want: []veles.Secret{
				mongodbatlasapikey.Credentials{
					PublicKey:  "abcd1234",
					PrivateKey: "12345678-abcd-1234-abcd-123456789abc",
				},
			},
		},
		// --- Terraform provider format ---
		{
			name: "terraform_provider",
			input: `provider "mongodbatlas" {
  public_key  = "yhrqvogk"
  private_key = "f2a79e29-8a44-4c75-a56d-5a4f7c6d1c97"
}`,
			want: []veles.Secret{
				mongodbatlasapikey.Credentials{
					PublicKey:  "yhrqvogk",
					PrivateKey: "f2a79e29-8a44-4c75-a56d-5a4f7c6d1c97",
				},
			},
		},
		// --- Keys too far apart (no pairing) ---
		{
			name: "keys_too_far_apart",
			input: `public_api_key = "yhrqvogk"` + strings.Repeat("\nfiller line with random data", 500) + `
private_api_key = "f2a79e29-8a44-4c75-a56d-5a4f7c6d1c97"`,
			want: nil,
		},
		// --- Invalid key formats ---
		{
			name:  "public_key_too_long",
			input: `public_api_key = "yhrqvogk123" private_api_key = "f2a79e29-8a44-4c75-a56d-5a4f7c6d1c97"`,
			want:  nil,
		},
		{
			name:  "private_key_not_uuid",
			input: `public_api_key = "yhrqvogk" private_api_key = "not-a-valid-uuid-format"`,
			want:  nil,
		},
		// --- Multiple key pairs ---
		{
			name: "multiple_key_pairs",
			input: `# Production
public_api_key = "prodkey1"
private_api_key = "11111111-1111-1111-1111-111111111111"

# Staging
public_api_key = "stagkey2"
private_api_key = "22222222-2222-2222-2222-222222222222"`,
			want: []veles.Secret{
				mongodbatlasapikey.Credentials{
					PublicKey:  "prodkey1",
					PrivateKey: "11111111-1111-1111-1111-111111111111",
				},
				mongodbatlasapikey.Credentials{
					PublicKey:  "stagkey2",
					PrivateKey: "22222222-2222-2222-2222-222222222222",
				},
			},
		},
		// --- Backtick-quoted values ---
		{
			name: "backtick_quoted_values",
			input: "public_api_key = `abcd1234`\nprivate_api_key = `f2a79e29-8a44-4c75-a56d-5a4f7c6d1c97`",
			want: []veles.Secret{
				mongodbatlasapikey.Credentials{
					PublicKey:  "abcd1234",
					PrivateKey: "f2a79e29-8a44-4c75-a56d-5a4f7c6d1c97",
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
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
