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

package sap_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/sap"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	validSAPAribaClientID     = "s7bafaef-016a-4426-8d05-8228fcf4ddc9"
	validSAPAribaClientSecret = "Gl9E5ssf2LV5ANUY3K2Y7goquSsP2y8F"
)

func TestSAPAribaClientCredentialsDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		sap.NewSAPAribaOAuth2ClientCredentialsDetector(),
		"client_id: "+validSAPAribaClientID+"\n"+"client_secret: "+validSAPAribaClientSecret,
		sap.AribaOAuth2ClientCredentials{ID: validSAPAribaClientID, Secret: validSAPAribaClientSecret},
	)
}

func TestSAPAribaClientCredentialsDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{sap.NewSAPAribaOAuth2ClientCredentialsDetector()})
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
			name:  "non_credential_input",
			input: "Some random text",
			want:  nil,
		},
		// --- One of Client ID or Client Secret or URL or Token URL ---
		{
			name:  "missing_client_id",
			input: "client_secret:" + validSAPAribaClientSecret,
			want:  nil,
		},
		{
			name:  "missing_client_secret",
			input: "client_id: " + validSAPAribaClientID,
			want:  nil,
		}, // --- Happy path ---
		{
			name: "valid_sap_ariba_client_credentials",
			input: `
client_id: ` + validSAPAribaClientID + `
client_secret: ` + validSAPAribaClientSecret,
			want: []veles.Secret{
				sap.AribaOAuth2ClientCredentials{
					ID:     validSAPAribaClientID,
					Secret: validSAPAribaClientSecret,
				},
			},
		},
		// --- Mixed valid & invalid ---
		{
			name: "mixed_valid_and_invalid",
			input: `
client_id: invalid-client-id
client_secret: wrongsecret

client_id: ` + validSAPAribaClientID + `
client_secret: ` + validSAPAribaClientSecret,
			want: []veles.Secret{
				sap.AribaOAuth2ClientCredentials{
					ID:     validSAPAribaClientID,
					Secret: validSAPAribaClientSecret,
				},
			},
		},
		// --- valid quoted ---
		{
			name: "valid_quoted",
			input: `
"client_id": "` + validSAPAribaClientID + `"
"client_secret": "` + validSAPAribaClientSecret + `"`,
			want: []veles.Secret{
				sap.AribaOAuth2ClientCredentials{
					ID:     validSAPAribaClientID,
					Secret: validSAPAribaClientSecret,
				},
			},
		},
		// --- overlong client ID and Secret ---
		{
			name: "invalid_overlong_client_id",
			input: `
"client_id": s7bafaef-016a-4426-8d05-8228fcf4ddc9000000000"` + `
"client_secret": "` + validSAPAribaClientSecret + `"`,
			want: nil,
		},
		{
			name: "invalid_overlong_client_secret",
			input: `
"client_id": "` + validSAPAribaClientID + `"
"client_secret": "Gl9E5ssf2LV5ANUY3K2Y7goquSsP2y8FYUV"`,
			want: nil,
		},
		// --- Hypenated client ID ---
		{
			name: "invalid_hypenated_client_id",
			input: `
"client_id": "` + validSAPAribaClientID + `-"
"client_secret": "` + validSAPAribaClientSecret + `"`,
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
