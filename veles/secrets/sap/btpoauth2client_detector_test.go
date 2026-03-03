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
	validBTPClientID      = "sb-cffc4197-e2bb-4a82-a127-8f202a3bb45c!b157978|it!b117912"
	validBTPXSUAAClientID = "sb-myappdemo!b157978"
	validBTPClientSecret  = "e602e1f0-dec1-45f5-8076-22508b2edb47$V8llAxOUna9EZRsVhWFk3zBkksspWrlF9ETuj2OZqr8="
	validBTPTokenURL      = "figafpartner-1.authentication.eu10.hana.ondemand.com/oauth/token"
)

func TestBTPOAuth2ClientCredentialsDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		sap.NewBTPOAuth2ClientCredentialsDetector(),
		validBTPClientID+"\n"+"client_secret: "+validBTPClientSecret+"\n"+validBTPTokenURL,
		sap.BTPOAuth2ClientCredentials{ID: validBTPClientID, Secret: validBTPClientSecret, TokenURL: validBTPTokenURL},
	)
}

func TestBTPXSUAAClientCredentialsDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		sap.NewBTPXSUAAOAuth2ClientCredentialsDetector(),
		validBTPXSUAAClientID+"\n"+"client_secret: "+validBTPClientSecret+"\n"+validBTPTokenURL,
		sap.BTPOAuth2ClientCredentials{ID: validBTPXSUAAClientID, Secret: validBTPClientSecret, TokenURL: validBTPTokenURL},
	)
}

func TestBTPOAuth2ClientCredentialsDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{sap.NewBTPOAuth2ClientCredentialsDetector()})
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
			name:  "invalid token url format",
			input: validBTPClientID + "\nclient_secret:" + validBTPClientSecret + "\nhttps://example.com/token",
			want:  nil,
		},
		// --- One of Client ID or Client Secret or URL or Token URL ---
		{
			name:  "missing client id",
			input: "client_secret:" + validBTPClientSecret + "\n" + validBTPTokenURL,
			want:  nil,
		},
		{
			name:  "missing client secret",
			input: validBTPClientID + "\n" + validBTPTokenURL,
			want:  nil,
		},
		{
			name:  "missing token url",
			input: validBTPClientID + "\n" + "client_secret:" + validBTPClientSecret,
			want:  nil,
		},
		// --- Happy path ---
		{
			name: "valid_sap_credentials",
			input: `
` + validBTPClientID + `
client_secret: ` + validBTPClientSecret + `
` + validBTPTokenURL + `
`,
			want: []veles.Secret{
				sap.BTPOAuth2ClientCredentials{
					ID:       validBTPClientID,
					Secret:   validBTPClientSecret,
					TokenURL: validBTPTokenURL,
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

` + validBTPClientID + `
client_secret: ` + validBTPClientSecret + `
` + validBTPTokenURL + `
`,
			want: []veles.Secret{
				sap.BTPOAuth2ClientCredentials{
					ID:       validBTPClientID,
					Secret:   validBTPClientSecret,
					TokenURL: validBTPTokenURL,
				},
			},
		},
		// --- Multiple valid credential blocks ---
		{
			name: "multiple_valid_credentials",
			input: `
app1:
` + validBTPClientID + `
client_secret: ` + validBTPClientSecret + `
` + validBTPTokenURL + `

app2:
` + validBTPClientID + `
client_secret: ` + validBTPClientSecret + `
` + validBTPTokenURL + `
`,
			want: []veles.Secret{
				sap.BTPOAuth2ClientCredentials{
					ID:       validBTPClientID,
					Secret:   validBTPClientSecret,
					TokenURL: validBTPTokenURL,
				},
				sap.BTPOAuth2ClientCredentials{
					ID:       validBTPClientID,
					Secret:   validBTPClientSecret,
					TokenURL: validBTPTokenURL,
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

func TestBTPXSUAAClientCredentialsDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{sap.NewBTPXSUAAOAuth2ClientCredentialsDetector()})
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
			name:  "invalid token url format",
			input: validBTPXSUAAClientID + "\nclient_secret:" + validBTPClientSecret + "\nhttps://example.com/token",
			want:  nil,
		},
		// --- One of Client ID or Client Secret or URL or Token URL ---
		{
			name:  "missing client id",
			input: "client_secret:" + validBTPClientSecret + "\n" + validBTPTokenURL,
			want:  nil,
		},
		{
			name:  "missing client secret",
			input: validBTPXSUAAClientID + "\n" + validBTPTokenURL,
			want:  nil,
		},
		{
			name:  "missing token url",
			input: validBTPXSUAAClientID + "\n" + "client_secret:" + validBTPClientSecret,
			want:  nil,
		},
		// --- Happy path ---
		{
			name: "valid_sap_credentials",
			input: `
` + validBTPXSUAAClientID + `
client_secret: ` + validBTPClientSecret + `
` + validBTPTokenURL + `
`,
			want: []veles.Secret{
				sap.BTPOAuth2ClientCredentials{
					ID:       validBTPXSUAAClientID,
					Secret:   validBTPClientSecret,
					TokenURL: validBTPTokenURL,
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

` + validBTPXSUAAClientID + `
client_secret: ` + validBTPClientSecret + `
` + validBTPTokenURL + `
`,
			want: []veles.Secret{
				sap.BTPOAuth2ClientCredentials{
					ID:       validBTPXSUAAClientID,
					Secret:   validBTPClientSecret,
					TokenURL: validBTPTokenURL,
				},
			},
		},
		// --- Multiple valid credential blocks ---
		{
			name: "multiple_valid_credentials",
			input: `
app1:
` + validBTPXSUAAClientID + `
client_secret: ` + validBTPClientSecret + `
` + validBTPTokenURL + `

app2:
` + validBTPXSUAAClientID + `
client_secret: ` + validBTPClientSecret + `
` + validBTPTokenURL + `
`,
			want: []veles.Secret{
				sap.BTPOAuth2ClientCredentials{
					ID:       validBTPXSUAAClientID,
					Secret:   validBTPClientSecret,
					TokenURL: validBTPTokenURL,
				},
				sap.BTPOAuth2ClientCredentials{
					ID:       validBTPXSUAAClientID,
					Secret:   validBTPClientSecret,
					TokenURL: validBTPTokenURL,
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
