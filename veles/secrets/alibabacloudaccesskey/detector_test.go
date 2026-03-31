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

package alibabacloudaccesskey_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/alibabacloudaccesskey"
	"github.com/google/osv-scalibr/veles/velestest"
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		alibabacloudaccesskey.NewDetector(),
		`LTAI5tB9hcbFSuN7nYnTqXkZ:zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n`,
		alibabacloudaccesskey.Credentials{AccessKeyID: `LTAI5tB9hcbFSuN7nYnTqXkZ`, AccessKeySecret: `zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n`},
	)
}

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{alibabacloudaccesskey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "empty_input",
			input: "",
			want:  nil,
		},
		{
			name:  "invalid_prefix",
			input: "ABCD5tB9hcbFSuN7nYnTqXkZ:zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n",
			want:  nil,
		},
		{
			name:  "access_key_id_too_short",
			input: "LTAI5tB9hcbFSuN7nYn:zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n",
			want:  nil,
		},
		{
			name:  "access_key_id_but_no_secret",
			input: "access_key_id: LTAI5tB9hcbFSuN7nYnTqXkZ",
			want:  nil,
		},
		{
			name:  "secret_but_no_access_key_id",
			input: "access_key_secret: zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n",
			want:  nil,
		},
		{
			name: "credentials_in_config_file",
			input: `[default]
access_key_id = LTAI5tB9hcbFSuN7nYnTqXkZ
access_key_secret = zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n`,
			want: []veles.Secret{
				alibabacloudaccesskey.Credentials{
					AccessKeyID:     "LTAI5tB9hcbFSuN7nYnTqXkZ",
					AccessKeySecret: "zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n",
				},
			},
		},
		{
			name:  "credentials_colon_separated",
			input: "LTAI5tB9hcbFSuN7nYnTqXkZ:zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n",
			want: []veles.Secret{
				alibabacloudaccesskey.Credentials{
					AccessKeyID:     "LTAI5tB9hcbFSuN7nYnTqXkZ",
					AccessKeySecret: "zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n",
				},
			},
		},
		{
			name: "credentials_in_json_format",
			input: `{
				"AccessKeyId": "LTAI5tB9hcbFSuN7nYnTqXkZ",
				"AccessKeySecret": "zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n"
			}`,
			want: []veles.Secret{
				alibabacloudaccesskey.Credentials{
					AccessKeyID:     "LTAI5tB9hcbFSuN7nYnTqXkZ",
					AccessKeySecret: "zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n",
				},
			},
		},
		{
			name: "credentials_in_env_file",
			input: `ALIBABA_CLOUD_ACCESS_KEY_ID=LTAI5tB9hcbFSuN7nYnTqXkZ
ALIBABA_CLOUD_ACCESS_KEY_SECRET=zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n`,
			want: []veles.Secret{
				alibabacloudaccesskey.Credentials{
					AccessKeyID:     "LTAI5tB9hcbFSuN7nYnTqXkZ",
					AccessKeySecret: "zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n",
				},
			},
		},
		{
			name: "multiple_credential_pairs",
			input: `config_app1:
LTAI5tB9hcbFSuN7nYnTqXkZ
zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n

config_app2:
LTAI4GHqHoxRFi4eaQqd3r5C
aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2`,
			want: []veles.Secret{
				alibabacloudaccesskey.Credentials{
					AccessKeyID:     "LTAI5tB9hcbFSuN7nYnTqXkZ",
					AccessKeySecret: "zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n",
				},
				alibabacloudaccesskey.Credentials{
					AccessKeyID:     "LTAI4GHqHoxRFi4eaQqd3r5C",
					AccessKeySecret: "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2",
				},
			},
		},
		{
			name: "credentials_far_apart_no_pairing",
			input: `config_app1:
LTAI5tB9hcbFSuN7nYnTqXkZ` + strings.Repeat("\nfiller line with random data", 500) + `
config_app2:
zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n`,
			want: nil,
		},
		{
			name:  "21_char_suffix_access_key_id",
			input: `LTAI5tB9hcbFSuN7nYnTqXkZa:zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n`,
			want: []veles.Secret{
				alibabacloudaccesskey.Credentials{
					AccessKeyID:     "LTAI5tB9hcbFSuN7nYnTqXkZa",
					AccessKeySecret: "zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n",
				},
			},
		},
		{
			name:  "17_char_suffix_access_key_id",
			input: `LTAI5tB9hcbFSuN7nYnTq:zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n`,
			want: []veles.Secret{
				alibabacloudaccesskey.Credentials{
					AccessKeyID:     "LTAI5tB9hcbFSuN7nYnTq",
					AccessKeySecret: "zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n",
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
