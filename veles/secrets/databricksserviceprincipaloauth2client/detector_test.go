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

package databricksserviceprincipaloauth2client_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/databricksserviceprincipaloauth2client"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	validClientID     = "7603a2a8-8220-485f-b2a5-58fa7b60a932"
	validClientSecret = "dose7d9f306280a357544b0655ed81ef06c9"
	validURL          = "adb-myworkspace.1233322.azuredatabricks.net"
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		databricksserviceprincipaloauth2client.NewDetector(),
		validURL+"\n"+validClientSecret+"\n"+"client_id:"+validClientID,
		databricksserviceprincipaloauth2client.Credentials{URL: validURL, Secret: validClientSecret, ID: validClientID},
	)
}

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{databricksserviceprincipaloauth2client.NewDetector()})
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
			name:  "invalid Client ID format - too short",
			input: "client_id: 76038-8220-485f-b2a5-58fa7932",
			want:  nil,
		},
		{
			name:  "invalid Client Secret format - wrong prefix",
			input: "bose7d9f306280a357544b0655ed81ef06c9",
			want:  nil,
		},
		{
			name:  "invalid Client Secret format - too short",
			input: "dose7d9f306280a357544",
			want:  nil,
		},
		{
			name:  "invalid workspace URL format - different URL",
			input: "adb-myworkspace.cloud.databrickss.com",
			want:  nil,
		},
		// --- One of Client ID or Client Secret or URL ---
		{
			name:  "Client ID but no Client Secret and Account ID",
			input: `client_id: 7603a2a8-8220-485f-b2a5-58fa7b60a932`,
			want:  nil,
		},
		{
			name:  "Client Secret but no Client ID and Account ID",
			input: `dose7d9f306280a357544b0655ed81ef06c9`,
			want:  nil,
		},
		{
			name:  "URL but no Client ID and Client Secret",
			input: `adb-myworkspace.1233322.azuredatabricks.net`,
			want:  nil,
		},
		// -- Single URL, Client Secret, and Client ID in close proximity (happy path) ---
		{
			name: "URL_Client_Secret_and_Client_ID_in_close_proximity",
			input: `
db-sme-111233333.cloud.databricks.com?o=myworkspace
dose7d9f306280a357544b0655ed81ef06c9
client_id: 7603a2a8-8220-485f-b2a5-58fa7b60a932
`,
			want: []veles.Secret{
				databricksserviceprincipaloauth2client.Credentials{
					URL:    "db-sme-111233333.cloud.databricks.com?o=myworkspace",
					Secret: "dose7d9f306280a357544b0655ed81ef06c9",
					ID:     "7603a2a8-8220-485f-b2a5-58fa7b60a932",
				},
			},
		},
		{
			name: "valid_formats_mixed_with_invalid",
			input: `
db-sme-111233333.cloud.databricks.com?o=myworkspace
db-sme-111233333.cloud.databrickss.com?o=myworkspace
valid_secret: dose7d9f306280a357544b0655ed81ef06c9
invalid_secret: bose7d9f306280a357544b0655ed81ef06c9
client_id: 7603a2a8-8220-485f-b2a5-58fa7b60a932
client_id: 7603a2a8/8220-485f-b2a5-58fa7b60a932
`,
			want: []veles.Secret{
				databricksserviceprincipaloauth2client.Credentials{
					URL:    "db-sme-111233333.cloud.databricks.com?o=myworkspace",
					Secret: "dose7d9f306280a357544b0655ed81ef06c9",
					ID:     "7603a2a8-8220-485f-b2a5-58fa7b60a932",
				},
			},
		},
		// -- Multiple Client ID, Client Secret, and Account ID in close proximity ---
		{
			name: "complex_file_with_multiple_client_ids_client_secrets_and_account_ids_-_test_proximity",
			input: `
config_application_1:
db-sme-1111222223333.cloud.databricks.com?o=myworkspace
dose7d9f306280a357544b0655ed81ef06c9
client_id: 7603a2a8-8220-485f-b2a5-58fa7b60a932

config_application_2:
db-sme-1111222224444.cloud.databricks.com?o=myworkspace
dose8d9f306280a357544b0655ed81ef06c9
client_id: 9603a2a8-8220-485f-b2a5-58fa7b60a932
`,
			want: []veles.Secret{
				databricksserviceprincipaloauth2client.Credentials{
					URL:    "db-sme-1111222223333.cloud.databricks.com?o=myworkspace",
					Secret: "dose7d9f306280a357544b0655ed81ef06c9",
					ID:     "7603a2a8-8220-485f-b2a5-58fa7b60a932",
				},
				databricksserviceprincipaloauth2client.Credentials{
					URL:    "db-sme-1111222224444.cloud.databricks.com?o=myworkspace",
					Secret: "dose8d9f306280a357544b0655ed81ef06c9",
					ID:     "9603a2a8-8220-485f-b2a5-58fa7b60a932",
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
