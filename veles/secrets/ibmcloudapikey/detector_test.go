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

package ibmcloudapikey_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/ibmcloudapikey"
	"github.com/google/osv-scalibr/veles/velestest"
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		ibmcloudapikey.NewDetector(),
		`ibm_api_key: hQ7IfkjEssAt7gM5M3CnDFqulKxOPtIxRuLNxSM4XxxS`,
		ibmcloudapikey.Secret{Key: `hQ7IfkjEssAt7gM5M3CnDFqulKxOPtIxRuLNxSM4XxxS`},
	)
}

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{ibmcloudapikey.NewDetector()})
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
			name:  "token_without_ibm_keyword",
			input: "api_key: hQ7IfkjEssAt7gM5M3CnDFqulKxOPtIxRuLNxSM4XxxS",
			want:  nil,
		},
		{
			name:  "ibm_keyword_without_token",
			input: "ibm cloud api key: too_short",
			want:  nil,
		},
		{
			name:  "token_too_short",
			input: "ibm_api_key: hQ7IfkjEssAt7gM5M3CnDFqulK",
			want:  nil,
		},
		{
			name:  "ibm_keyword_and_token_in_close_proximity",
			input: `ibm_api_key: hQ7IfkjEssAt7gM5M3CnDFqulKxOPtIxRuLNxSM4XxxS`,
			want: []veles.Secret{
				ibmcloudapikey.Secret{Key: "hQ7IfkjEssAt7gM5M3CnDFqulKxOPtIxRuLNxSM4XxxS"},
			},
		},
		{
			name: "ibm_cloud_credentials_file",
			input: `[default]
apikey = Re34sdGs2ACMEfrtz2-2FeRxgB1KHjYhBpFo7dLRz2bx
url = https://iam.cloud.ibm.com/identity/token`,
			want: []veles.Secret{
				ibmcloudapikey.Secret{Key: "Re34sdGs2ACMEfrtz2-2FeRxgB1KHjYhBpFo7dLRz2bx"},
			},
		},
		{
			name:  "ibm_env_var_format",
			input: `export IBM_API_KEY=hQ7IfkjEssAt7gM5M3CnDFqulKxOPtIxRuLNxSM4XxxS`,
			want: []veles.Secret{
				ibmcloudapikey.Secret{Key: "hQ7IfkjEssAt7gM5M3CnDFqulKxOPtIxRuLNxSM4XxxS"},
			},
		},
		{
			name: "ibm_json_config",
			input: `{
				"ibm_cloud": {
					"apikey": "Re34sdGs2ACMEfrtz2-2FeRxgB1KHjYhBpFo7dLRz2bx"
				}
			}`,
			want: []veles.Secret{
				ibmcloudapikey.Secret{Key: "Re34sdGs2ACMEfrtz2-2FeRxgB1KHjYhBpFo7dLRz2bx"},
			},
		},
		{
			name:  "bluemix_keyword",
			input: `BLUEMIX_API_KEY=hQ7IfkjEssAt7gM5M3CnDFqulKxOPtIxRuLNxSM4XxxS`,
			want: []veles.Secret{
				ibmcloudapikey.Secret{Key: "hQ7IfkjEssAt7gM5M3CnDFqulKxOPtIxRuLNxSM4XxxS"},
			},
		},
		{
			name:  "token_too_far_from_keyword",
			input: `ibm_config: true` + strings.Repeat("\nfiller line with random data", 100) + "\napikey = hQ7IfkjEssAt7gM5M3CnDFqulKxOPtIxRuLNxSM4XxxS",
			want:  nil,
		},
		{
			name: "multiple_ibm_keys",
			input: `ibm_key1 = hQ7IfkjEssAt7gM5M3CnDFqulKxOPtIxRuLNxSM4XxxS
ibm_key2 = Re34sdGs2ACMEfrtz2-2FeRxgB1KHjYhBpFo7dLRz2bx`,
			want: []veles.Secret{
				ibmcloudapikey.Secret{Key: "hQ7IfkjEssAt7gM5M3CnDFqulKxOPtIxRuLNxSM4XxxS"},
				ibmcloudapikey.Secret{Key: "Re34sdGs2ACMEfrtz2-2FeRxgB1KHjYhBpFo7dLRz2bx"},
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
