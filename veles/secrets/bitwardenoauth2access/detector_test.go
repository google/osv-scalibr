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

package bitwardenoauth2access_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/bitwardenoauth2access"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	testUUID   = "d351d93b-adb0-4714-bbef-a11100fff9cc"
	testSecret = "N8N2xWg4FV8lusbl5CHBb5XRil6kOa"
)

var testInput = `"user_` + testUUID + `_token_apiKeyClientSecret": "` + testSecret + `"`

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		bitwardenoauth2access.NewDetector(),
		testInput,
		bitwardenoauth2access.Token{ClientID: testUUID, ClientSecret: testSecret},
	)
}

// TestDetector_truePositives tests for cases where we know the Detector
// will find a Bitwarden OAuth2 access token.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{bitwardenoauth2access.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "standard Bitwarden data.json entry",
			input: `"user_d351d93b-adb0-4714-bbef-a11100fff9cc_token_apiKeyClientSecret": "N8N2xWg4FV8lusbl5CHBb5XRil6kOa"`,
			want: []veles.Secret{
				bitwardenoauth2access.Token{ClientID: "d351d93b-adb0-4714-bbef-a11100fff9cc", ClientSecret: "N8N2xWg4FV8lusbl5CHBb5XRil6kOa"},
			},
		},
		{
			name:  "different UUID",
			input: `"user_a1b2c3d4-e5f6-7890-abcd-ef1234567890_token_apiKeyClientSecret": "AbCdEfGhIjKlMnOpQrStUvWxYz123456"`,
			want: []veles.Secret{
				bitwardenoauth2access.Token{ClientID: "a1b2c3d4-e5f6-7890-abcd-ef1234567890", ClientSecret: "AbCdEfGhIjKlMnOpQrStUvWxYz123456"},
			},
		},
		{
			name: "embedded in larger JSON",
			input: `{
  "user_d351d93b-adb0-4714-bbef-a11100fff9cc_token_accessToken": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMwMDA...",
  "user_d351d93b-adb0-4714-bbef-a11100fff9cc_token_apiKeyClientSecret": "N8N2xWg4FV8lusbl5CHBb5XRil6kOa",
  "user_d351d93b-adb0-4714-bbef-a11100fff9cc_token_refreshToken": "someRefreshToken"
}`,
			want: []veles.Secret{
				bitwardenoauth2access.Token{ClientID: "d351d93b-adb0-4714-bbef-a11100fff9cc", ClientSecret: "N8N2xWg4FV8lusbl5CHBb5XRil6kOa"},
			},
		},
		{
			name: "multiple users in same file",
			input: `{
  "user_d351d93b-adb0-4714-bbef-a11100fff9cc_token_apiKeyClientSecret": "N8N2xWg4FV8lusbl5CHBb5XRil6kOa",
  "user_a1b2c3d4-e5f6-7890-abcd-ef1234567890_token_apiKeyClientSecret": "AbCdEfGhIjKlMnOpQrStUvWxYz123456"
}`,
			want: []veles.Secret{
				bitwardenoauth2access.Token{ClientID: "d351d93b-adb0-4714-bbef-a11100fff9cc", ClientSecret: "N8N2xWg4FV8lusbl5CHBb5XRil6kOa"},
				bitwardenoauth2access.Token{ClientID: "a1b2c3d4-e5f6-7890-abcd-ef1234567890", ClientSecret: "AbCdEfGhIjKlMnOpQrStUvWxYz123456"},
			},
		},
		{
			name:  "with extra whitespace around colon",
			input: `"user_d351d93b-adb0-4714-bbef-a11100fff9cc_token_apiKeyClientSecret"  :  "N8N2xWg4FV8lusbl5CHBb5XRil6kOa"`,
			want: []veles.Secret{
				bitwardenoauth2access.Token{ClientID: "d351d93b-adb0-4714-bbef-a11100fff9cc", ClientSecret: "N8N2xWg4FV8lusbl5CHBb5XRil6kOa"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty(), cmpopts.SortSlices(func(a, b veles.Secret) bool {
				ta, tb := a.(bitwardenoauth2access.Token), b.(bitwardenoauth2access.Token)
				return ta.ClientID < tb.ClientID
			})); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDetector_trueNegatives tests for cases where we know the Detector
// will not find a Bitwarden OAuth2 access token.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{bitwardenoauth2access.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "empty input",
			input: "",
		},
		{
			name:  "secret without keyword pattern",
			input: `"someKey": "N8N2xWg4FV8lusbl5CHBb5XRil6kOa"`,
		},
		{
			name:  "keyword without valid UUID",
			input: `"user_not-a-uuid_token_apiKeyClientSecret": "N8N2xWg4FV8lusbl5CHBb5XRil6kOa"`,
		},
		{
			name:  "keyword without secret value",
			input: `"user_d351d93b-adb0-4714-bbef-a11100fff9cc_token_apiKeyClientSecret": ""`,
		},
		{
			name:  "secret too short",
			input: `"user_d351d93b-adb0-4714-bbef-a11100fff9cc_token_apiKeyClientSecret": "short"`,
		},
		{
			name:  "unrelated JSON data",
			input: `{"name": "test", "version": "1.0.0"}`,
		},
	}
	for _, tc := range cases {
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
