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

package awsaccesskey_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/awsaccesskey"
)

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{awsaccesskey.NewDetector()})
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
			name:  "invalid_access_id_format_-_wrong prefix",
			input: "WRONG984R439T439HTH439T403TJ430TK340TK43T430JT430TK430JT043JT:32r923jr023rk320rk2a3rkB34tj340r32Ckt433",
			want:  nil,
		},
		{
			name:  "invalid_secret_format_-_too short",
			input: "GOOG1984R439T439HTH439T403TJ430TK340TK43T430JT430TK430JT043JT:32r923jr023rk320rk2a3rkB34tj3",
			want:  nil,
		},
		// --- Only access ID or Secret ---
		{
			name:  "access_ID_but_no_secret",
			input: `app_id: AKIA1984R439T439HTH4`,
			want:  nil,
		},
		{
			name:  "secret_but_no_access_ID",
			input: `app_secret: 32r923jr023rk320rk2a3rkB34tj340r32Ckt433`,
			want:  nil,
		},
		// -- Single access ID and Secret in close proximity (happy path) ---
		{
			name: "aws credentials",
			input: `[default]
aws_access_key_id = AKIA1984R439T439HTH4
aws_secret_access_key = 32r923jr023rk320rk2a3rkB34tj340r32Ckt433`,
			want: []veles.Secret{
				awsaccesskey.Credentials{
					AccessID: "AKIA1984R439T439HTH4",
					Secret:   "32r923jr023rk320rk2a3rkB34tj340r32Ckt433",
				},
			},
		},
		{
			name:  "access_ID_and_secret_in_close_proximity_-_no_space",
			input: `AKIA1984R439T439HTH4:32r923jr023rk320rk2a3rkB34tj340r32Ckt433`,
			want: []veles.Secret{
				awsaccesskey.Credentials{
					AccessID: "AKIA1984R439T439HTH4",
					Secret:   "32r923jr023rk320rk2a3rkB34tj340r32Ckt433",
				},
			},
		},
		{
			name: "access_ID_and_secret_in_close_proximity_in_json_format",
			input: `{
				"access_id": "AKIA1984R439T439HTH4",
				"secret": "32r923jr023rk320rk2a3rkB34tj340r32Ckt433"
			}`,
			want: []veles.Secret{
				awsaccesskey.Credentials{
					AccessID: "AKIA1984R439T439HTH4",
					Secret:   "32r923jr023rk320rk2a3rkB34tj340r32Ckt433",
				},
			},
		},
		{
			name: "valid_formats_mixed_with_invalid",
			input: `valid_id: AKIA1984R439T439HTH4
invalid_id: 123-invalid.apps.googleusercontent.com
valid_secret: 32r923jr023rk320rk2a3rkB34tj340r32Ckt433
invalid_secret: WRONG-InvalidSecret123456789012`,
			want: []veles.Secret{
				awsaccesskey.Credentials{
					AccessID: "AKIA1984R439T439HTH4",
					Secret:   "32r923jr023rk320rk2a3rkB34tj340r32Ckt433",
				},
			},
		},
		// -- Multiple access ID and Secret in close proximity ---
		{
			name: "complex_file_with_multiple_access_ID_and_secret_-_test_proximity",
			input: `config_app1:
			AKIA1984R439T439HTH4
32r923jr023rk320rk2a3rkB34tj340r32Ckt433

config_app2:
AKIA1984R439T439HTH3
32r923jr023rk320rk2a3rkB34tj340r32Ckt432`,
			want: []veles.Secret{
				awsaccesskey.Credentials{
					AccessID: "AKIA1984R439T439HTH4",
					Secret:   "32r923jr023rk320rk2a3rkB34tj340r32Ckt433",
				},
				awsaccesskey.Credentials{
					AccessID: "AKIA1984R439T439HTH3",
					Secret:   "32r923jr023rk320rk2a3rkB34tj340r32Ckt432",
				},
			},
		},
		// -- Multiple access ID and Secret in with varied proximity ---
		{
			name: "complex_file_with_access_ID_and_secret_-_far_apart_(no_pairing)",
			input: `config_app1:
AKIA1984R439T439HTH4` + strings.Repeat("\nfiller line with random data", 500) + `
config_app2:
32r923jr023rk320rk2a3rkB34tj340r32Ckt432`,
			want: nil,
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
