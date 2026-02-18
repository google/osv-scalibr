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

package databricksuseraccountpat_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/databricksuseraccountpat"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	validPATToken  = "dapiec91f46edff7a4ecae11005e2dcd21e5"
	validAccountID = "bd59efba-4444-4444-443f-44444449203"
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		databricksuseraccountpat.NewDetector(),
		validPATToken+"\n"+"account_id:"+validAccountID,
		databricksuseraccountpat.Credentials{Token: validPATToken, AccountID: validAccountID},
	)
}

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{databricksuseraccountpat.NewDetector()})
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
			name:  "invalid PAT format - wrong prefix",
			input: "papiec91f46edff7a4ecae11005e2dcd21e5",
			want:  nil,
		},
		{
			name:  "invalid PAT format - too short",
			input: "dapiec91f46edff",
			want:  nil,
		},
		{
			name:  "invalid Account ID format - underscore",
			input: "bd59efba-4444-4444-443f-4444444_203",
			want:  nil,
		},
		{
			name:  "invalid Account ID format - too short",
			input: "bd59efba-4444-4444",
			want:  nil,
		},
		// --- Only PAT Token or Account ID ---
		{
			name:  "PAT Token but no Account ID",
			input: `dapiec91f46edff7a4ecae11005e2dcd21e5`,
			want:  nil,
		},
		{
			name:  "Account ID but no PAT Token",
			input: `account_id: bd59efba-4444-4444-443f-44444449203`,
			want:  nil,
		},
		// -- Single PAT Token and Account ID in close proximity (happy path) ---
		{
			name: "PAT_and_Account_ID_in_close_proximity",
			input: `
dapiec91f46edff7a4ecae11005e2dcd21e5
account_id: bd59efba-4444-4444-443f-44444449203
`,
			want: []veles.Secret{
				databricksuseraccountpat.Credentials{
					Token:     "dapiec91f46edff7a4ecae11005e2dcd21e5",
					AccountID: "bd59efba-4444-4444-443f-44444449203",
				},
			},
		},
		{
			name:  "Account_ID_in_with_invalid_format",
			input: `papiec91f46edff7a4ecae11005e2dcd21e5`,
			want:  nil,
		},
		{
			name: "valid_formats_mixed_with_invalid",
			input: `
valid_pat: dapiec91f46edff7a4ecae11005e2dcd21e5
invalid_pat: papiec91f46edff7a4ecae11005e2dcd21e5
account_id: bd59efba-4444-4444-443f-44444449203
account_id: bd59efba-4444-4444-443f-4444444920`,
			want: []veles.Secret{
				databricksuseraccountpat.Credentials{
					Token:     "dapiec91f46edff7a4ecae11005e2dcd21e5",
					AccountID: "bd59efba-4444-4444-443f-44444449203",
				},
			},
		},
		// -- Multiple PAT Tokens and Account ID in close proximity ---
		{
			name: "complex_file_with_multiple_pats_and_account_id_-_test_proximity",
			input: `
config_application_1:
dapiec91f46edff7a4ecae11005e2dcd21e5
account_id: ef59efba-4444-4444-443f-44444449203

config_application_2:
dapi56eae0fe6bfaa9ea26eb3fa32ad6f8cb-3
account_id: bd59efba-4444-4444-443f-44444449203`,
			want: []veles.Secret{
				databricksuseraccountpat.Credentials{
					Token:     "dapiec91f46edff7a4ecae11005e2dcd21e5",
					AccountID: "ef59efba-4444-4444-443f-44444449203",
				},
				databricksuseraccountpat.Credentials{
					Token:     "dapi56eae0fe6bfaa9ea26eb3fa32ad6f8cb-3",
					AccountID: "bd59efba-4444-4444-443f-44444449203",
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
