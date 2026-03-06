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

package databricks_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/databricks"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	validPATToken = "dapiec91f46edff7a4ecae11005e2dcd21e5"
	validSPPATURL = "my-workspace.gcp.databricks.com"
)

func TestSPPATDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		databricks.NewSPPATDetector(),
		validPATToken+"\n"+validSPPATURL,
		databricks.SPPATCredentials{Token: validPATToken, URL: validSPPATURL},
	)
}

func TestSPPATDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{databricks.NewSPPATDetector()})
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
			name:  "invalid workspace URL format - different URL",
			input: "abc123.cloud.databrickss.com",
			want:  nil,
		},
		// --- Only PAT Token or Workspace URL ---
		{
			name:  "PAT Token but no URL",
			input: `dapiec91f46edff7a4ecae11005e2dcd21e5`,
			want:  nil,
		},
		{
			name:  "URL but no PAT Token",
			input: `abc123.cloud.databricks.com`,
			want:  nil,
		},
		// -- Single PAT Token and URL in close proximity (happy path) ---
		{
			name: "PAT_and_URL_in_close_proximity",
			input: `
dapiec91f46edff7a4ecae11005e2dcd21e5
prod-01.azuredatabricks.net
`,
			want: []veles.Secret{
				databricks.SPPATCredentials{
					Token: "dapiec91f46edff7a4ecae11005e2dcd21e5",
					URL:   "prod-01.azuredatabricks.net",
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
prod-01.azuredatabricks.net
prod-01.azuredatabrickss.net`,
			want: []veles.Secret{
				databricks.SPPATCredentials{
					Token: "dapiec91f46edff7a4ecae11005e2dcd21e5",
					URL:   "prod-01.azuredatabricks.net",
				},
			},
		},
		// -- Multiple PAT Tokens and Account ID in close proximity ---
		{
			name: "complex_file_with_multiple_pats_and_account_id_-_test_proximity",
			input: `
config_application_1:
dapiec91f46edff7a4ecae11005e2dcd21e5
my-workspace.gcp.databricks.com

config_application_2:
dapi56eae0fe6bfaa9ea26eb3fa32ad6f8cb-3
prod-01.azuredatabricks.net

config_application_3:
dapi56eae0fe6bfaa9ea26eb3fa32ad6f8cb-4
abc123.cloud.databricks.com`,
			want: []veles.Secret{
				databricks.SPPATCredentials{
					Token: "dapiec91f46edff7a4ecae11005e2dcd21e5",
					URL:   "my-workspace.gcp.databricks.com",
				},
				databricks.SPPATCredentials{
					Token: "dapi56eae0fe6bfaa9ea26eb3fa32ad6f8cb-3",
					URL:   "prod-01.azuredatabricks.net",
				},
				databricks.SPPATCredentials{
					Token: "dapi56eae0fe6bfaa9ea26eb3fa32ad6f8cb-4",
					URL:   "abc123.cloud.databricks.com",
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
