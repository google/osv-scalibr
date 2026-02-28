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

package databricksuseraccountoauth2client_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/databricksuseraccountoauth2client"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	validClientID     = "7603a2a8-8220-485f-b2a5-58fa7b60a932"
	validClientSecret = "dose7d9f306280a357544b0655ed81ef06c9"
	validAccountID    = "bd59efba-4444-4444-443f-44444449203"
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		databricksuseraccountoauth2client.NewDetector(),
		"client_id:"+validClientID+"\n"+validClientSecret+"\n"+"account_id:"+validAccountID,
		databricksuseraccountoauth2client.Credentials{ID: validClientID, Secret: validClientSecret, AccountID: validAccountID},
	)
}

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{databricksuseraccountoauth2client.NewDetector()})
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
			name:  "invalid Client ID format - wrong prefix",
			input: "bose7d9f306280a357544b0655ed81ef06c9",
			want:  nil,
		},
		{
			name:  "invalid Client ID format - too short",
			input: "dose7d9f306280a357544",
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
		// --- One of Client ID or Client Secret or Account ID ---
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
			name:  "Account ID but no Client ID and Client Secret",
			input: `account_id: bd59efba-4444-4444-443f-44444449203`,
			want:  nil,
		},
		// -- Single Client ID, Client Secret, and Account ID in close proximity (happy path) ---
		{
			name: "Client_ID_Client_Secret_and_Account_ID_in_close_proximity",
			input: `
client_id: 7603a2a8-8220-485f-b2a5-58fa7b60a932
dose7d9f306280a357544b0655ed81ef06c9
account_id: bd59efba-4444-4444-443f-44444449203
`,
			want: []veles.Secret{
				databricksuseraccountoauth2client.Credentials{
					ID:        "7603a2a8-8220-485f-b2a5-58fa7b60a932",
					Secret:    "dose7d9f306280a357544b0655ed81ef06c9",
					AccountID: "bd59efba-4444-4444-443f-44444449203",
				},
			},
		},
		{
			name: "valid_formats_mixed_with_invalid",
			input: `
client_id: 7603a2a8-8220-485f-b2a5-58fa7b60a932
client_id: 7603a2a8/8220-485f-b2a5-58fa7b60a932
valid_secret: dose7d9f306280a357544b0655ed81ef06c9
invalid_secret: bose7d9f306280a357544b0655ed81ef06c9
account_id: bd59efba-4444-4444-443f-44444449203
account_id: bd59efba-4444-4444-443f-4444444920`,
			want: []veles.Secret{
				databricksuseraccountoauth2client.Credentials{
					Secret:    "dose7d9f306280a357544b0655ed81ef06c9",
					ID:        "7603a2a8-8220-485f-b2a5-58fa7b60a932",
					AccountID: "bd59efba-4444-4444-443f-44444449203",
				},
			},
		},
		// -- Multiple Client ID, Client Secret, and Account ID in close proximity ---
		{
			name: "complex_file_with_multiple_client_ids_client_secrets_and_account_ids_-_test_proximity",
			input: `
config_application_1:
client_id: 7603a2a8-8220-485f-b2a5-58fa7b60a932
dose7d9f306280a357544b0655ed81ef06c9
account_id: bd59efba-4444-4444-443f-44444449203

config_application_2:
client_id: 9603a2a8-8220-485f-b2a5-58fa7b60a932
dose8d9f306280a357544b0655ed81ef06c9
account_id: ef59efba-4444-4444-443f-44444449203`,
			want: []veles.Secret{
				databricksuseraccountoauth2client.Credentials{
					Secret:    "dose7d9f306280a357544b0655ed81ef06c9",
					ID:        "7603a2a8-8220-485f-b2a5-58fa7b60a932",
					AccountID: "bd59efba-4444-4444-443f-44444449203",
				},
				databricksuseraccountoauth2client.Credentials{
					Secret:    "dose8d9f306280a357544b0655ed81ef06c9",
					ID:        "9603a2a8-8220-485f-b2a5-58fa7b60a932",
					AccountID: "ef59efba-4444-4444-443f-44444449203",
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
