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

package sapoauth2client_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/sapoauth2client"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	validClientID     = "sb-cffc4197-e2bb-4a82-a127-8f202a3bb45c!b157978|it!b117912"
	validClientSecret = "e602e1f0-dec1-45f5-8076-22508b2edb47$V8llAxOUna9EZRsVhWFk3zBkksspWrlF9ETuj2OZqr8="
	validTokenURL     = "figafpartner-1.authentication.eu10.hana.ondemand.com/oauth/token"
	validURL          = "figafpartner-1.it-cpi018.cfapps.eu10-003.hana.ondemand.com"
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		sapoauth2client.NewDetector(),
		validClientID+"\n"+"client_secret: "+validClientSecret+"\n"+validURL+"\n"+validTokenURL,
		sapoauth2client.Credentials{ID: validClientID, Secret: validClientSecret, TokenURL: validTokenURL, URL: validURL},
	)
}

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{sapoauth2client.NewDetector()})
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
			input: "sb-abc",
			want:  nil,
		},
		{
			name:  "invalid Client Secret format - too short",
			input: "client_secret: abc-bcd-ef",
			want:  nil,
		},
		{
			name:  "invalid url format",
			input: validClientID + "\nclient_secret:" + validClientSecret + "\nhttps://example.com\n" + validTokenURL,
			want:  nil,
		},
		{
			name:  "invalid token url format",
			input: validClientID + "\nclient_secret:" + validClientSecret + "\n" + validURL + "\nhttps://example.com/token",
			want:  nil,
		},
		// --- One of Client ID or Client Secret or URL or Token URL ---
		{
			name: "missing client id",
			input: "client_secret:" + validClientSecret + "\n" +
				validURL + "\n" +
				validTokenURL,
			want: nil,
		},
		{
			name: "missing client secret",
			input: validClientID + "\n" +
				validURL + "\n" +
				validTokenURL,
			want: nil,
		},
		{
			name: "missing token url",
			input: validClientID + "\n" +
				"client_secret:" + validClientSecret + "\n" +
				validURL,
			want: nil,
		},
		{
			name: "missing url",
			input: validClientID + "\n" +
				"client_secret:" + validClientSecret + "\n" +
				validTokenURL,
			want: nil,
		},
		// --- Happy path ---
		{
			name: "valid_sap_credentials",
			input: `
` + validClientID + `
client_secret: ` + validClientSecret + `
` + validURL + `
` + validTokenURL + `
`,
			want: []veles.Secret{
				sapoauth2client.Credentials{
					ID:       validClientID,
					Secret:   validClientSecret,
					URL:      validURL,
					TokenURL: validTokenURL,
				},
			},
		},
		// --- Mixed valid & invalid ---
		{
			name: "mixed_valid_and_invalid",
			input: `
invalid-client-id
client_secret: wrongsecret
https://not-sap.com/token

` + validClientID + `
client_secret: ` + validClientSecret + `
` + validURL + `
` + validTokenURL + `
`,
			want: []veles.Secret{
				sapoauth2client.Credentials{
					ID:       validClientID,
					Secret:   validClientSecret,
					URL:      validURL,
					TokenURL: validTokenURL,
				},
			},
		},
		// --- Multiple valid credential blocks ---
		{
			name: "multiple_valid_credentials",
			input: `
app1:
` + validClientID + `
client_secret: ` + validClientSecret + `
` + validURL + `
` + validTokenURL + `

app2:
` + validClientID + `
client_secret: ` + validClientSecret + `
` + validURL + `
` + validTokenURL + `
`,
			want: []veles.Secret{
				sapoauth2client.Credentials{
					ID:       validClientID,
					Secret:   validClientSecret,
					URL:      validURL,
					TokenURL: validTokenURL,
				},
				sapoauth2client.Credentials{
					ID:       validClientID,
					Secret:   validClientSecret,
					URL:      validURL,
					TokenURL: validTokenURL,
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
