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

package ibmclouduserkey_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/ibmclouduserkey"
)

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{ibmclouduserkey.NewDetector()})
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
			name:  "invalid_key_format_too_short",
			input: "ibm xGS5JUV2Atr4-nBYM9AAYG91y-1234-sFAAKtsbua",
			want:  nil,
		},
		{
			name:  "ibm_keyword_but_no_secret",
			input: `ibm: IKA1984R439T439HTH4`,
			want:  nil,
		},
		{
			name:  "false_positive_key_but_no_keyword",
			input: `falsealarm: xGS5JUV2Atr4-nBYM9AAYG91y-1234-sFAAKtsbuafff`,
			want:  nil,
		},
		{
			name:  "valid_user_key_with_ibm_keyword",
			input: `ibm: xGS5JUV2Atr4-nBYM9AAYG91y-1234-sFAAKtsbuafff`,
			want: []veles.Secret{
				ibmclouduserkey.IBMCloudUserSecret{
					Key: "xGS5JUV2Atr4-nBYM9AAYG91y-1234-sFAAKtsbuafff",
				},
			},
		},
		{
			name: "far_apart_token",
			input: `ibm:
AAAAAAAAAA` + strings.Repeat("\nfiller line with random data", 500) + `
xGS5JUV2Atr4-nBYM9AAYG91y-1234-sFAAKtsbuafff`,
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
