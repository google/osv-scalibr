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
	validSAPConcurClientSecret = "a8bafaef-016a-4426-8d05-8228fcf4ddc9"
	validSAPConcurRefreshToken = "Gj9E5ssf2LV5ANUY3K2Y7goquSsP2y8F"
)

func TestSAPConcurRefreshTokenDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		sap.NewSAPConcurRefreshTokenDetector(),
		"client_id: "+validSAPAribaClientID+"\n"+"client_secret: "+validSAPConcurClientSecret+"\n"+"refresh_token: "+validSAPConcurRefreshToken,
		sap.ConcurRefreshToken{ID: validSAPAribaClientID, Secret: validSAPConcurClientSecret, Token: validSAPConcurRefreshToken},
	)
}

func TestSAPConcurRefreshTokenDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{sap.NewSAPConcurRefreshTokenDetector()})
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
		// --- One of Client ID or Client Secret or URL or Token URL ---
		{
			name:  "missing client id",
			input: "client_secret:" + validSAPConcurClientSecret + "\nrefresh_token: " + validSAPConcurRefreshToken,
			want:  nil,
		},
		{
			name:  "missing client secret",
			input: "client_id: " + validSAPAribaClientID + "\nrefresh_token: " + validSAPConcurRefreshToken,
			want:  nil,
		},
		{
			name:  "missing refresh token",
			input: "client_id: " + validSAPAribaClientID + "\nclient_secret:" + validSAPConcurClientSecret,
			want:  nil,
		},
		// --- Happy path ---
		{
			name: "valid_sap_concur_client_credentials",
			input: `
client_id: ` + validSAPAribaClientID + `
client_secret: ` + validSAPConcurClientSecret + `
refresh_token: ` + validSAPConcurRefreshToken,
			want: []veles.Secret{
				sap.ConcurRefreshToken{
					ID:     validSAPAribaClientID,
					Secret: validSAPConcurClientSecret,
					Token:  validSAPConcurRefreshToken,
				},
			},
		},
		// --- Mixed valid & invalid ---
		{
			name: "mixed_valid_and_invalid",
			input: `
client_id: invalid-client-id
client_secret: wrongsecret
refresh_token: a-b

client_id: ` + validSAPAribaClientID + `
client_secret: ` + validSAPConcurClientSecret + `
refresh_token: ` + validSAPConcurRefreshToken,
			want: []veles.Secret{
				sap.ConcurRefreshToken{
					ID:     validSAPAribaClientID,
					Secret: validSAPConcurClientSecret,
					Token:  validSAPConcurRefreshToken,
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
