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

package linearapikey_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/linearapikey"
	"github.com/google/osv-scalibr/veles/velestest"
)

// Fake Linear API keys for testing. These are NOT real keys.
const testLinearAPIKey = "lin_api_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testLinearAPIKey2 = "lin_api_1234567890abcdefghijklmnopqrstuvwxyz1234"

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		linearapikey.NewDetector(),
		testLinearAPIKey,
		linearapikey.APIKey{Key: testLinearAPIKey},
	)
}

func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{
		linearapikey.NewDetector(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "simple matching string",
			input: testLinearAPIKey,
			want: []veles.Secret{
				linearapikey.APIKey{Key: testLinearAPIKey},
			},
		},
		{
			name:  "key in env var",
			input: "LINEAR_API_KEY=" + testLinearAPIKey,
			want: []veles.Secret{
				linearapikey.APIKey{Key: testLinearAPIKey},
			},
		},
		{
			name:  "key in JSON",
			input: `{"linear_api_key": "` + testLinearAPIKey + `"}`,
			want: []veles.Secret{
				linearapikey.APIKey{Key: testLinearAPIKey},
			},
		},
		{
			name:  "multiple matches",
			input: testLinearAPIKey + "\n" + testLinearAPIKey2,
			want: []veles.Secret{
				linearapikey.APIKey{Key: testLinearAPIKey},
				linearapikey.APIKey{Key: testLinearAPIKey2},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetector_falsePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{
		linearapikey.NewDetector(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "wrong prefix",
			input: "lin_api_key_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			name:  "too short",
			input: "lin_api_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			name:  "too long",
			input: "lin_api_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			name:  "non-alphanumeric suffix",
			input: "lin_api_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!",
		},
		{
			name:  "mixed case prefix",
			input: "LIN_API_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) > 0 {
				t.Errorf("Detect() expected no secrets, got %v", got)
			}
		})
	}
}
