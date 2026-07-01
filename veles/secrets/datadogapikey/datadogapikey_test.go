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

package datadogapikey_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/datadogapikey"
	"github.com/google/osv-scalibr/veles/velestest"
)

// Fake Datadog API keys for testing. These are NOT real keys.
const testDatadogAPIKey = "a1b2c3d4e5f678901234567890123456"
const testDatadogAPIKey2 = "1234567890abcdef1234567890abcdef"

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		datadogapikey.NewDetector(),
		"DD_API_KEY="+testDatadogAPIKey,
		datadogapikey.APIKey{Key: testDatadogAPIKey},
	)
}

func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{
		datadogapikey.NewDetector(),
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
			name:  "DD_API_KEY environment variable",
			input: "DD_API_KEY=" + testDatadogAPIKey,
			want: []veles.Secret{
				datadogapikey.APIKey{Key: testDatadogAPIKey},
			},
		},
		{
			name:  "DATADOG_API_KEY environment variable",
			input: "DATADOG_API_KEY=" + testDatadogAPIKey2,
			want: []veles.Secret{
				datadogapikey.APIKey{Key: testDatadogAPIKey2},
			},
		},
		{
			name:  "quoted JSON key",
			input: `{"datadog_api_key": "` + testDatadogAPIKey + `"}`,
			want: []veles.Secret{
				datadogapikey.APIKey{Key: testDatadogAPIKey},
			},
		},
		{
			name:  "YAML config key",
			input: "DD_API_TOKEN: " + testDatadogAPIKey,
			want: []veles.Secret{
				datadogapikey.APIKey{Key: testDatadogAPIKey},
			},
		},
		{
			name:  "multiple matches",
			input: "DD_API_KEY=" + testDatadogAPIKey + "\nDATADOG_API_KEY=" + testDatadogAPIKey2,
			want: []veles.Secret{
				datadogapikey.APIKey{Key: testDatadogAPIKey},
				datadogapikey.APIKey{Key: testDatadogAPIKey2},
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
		datadogapikey.NewDetector(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "32 hex without keyword",
			input: testDatadogAPIKey,
		},
		{
			name:  "wrong keyword",
			input: "OTHER_API_KEY=" + testDatadogAPIKey,
		},
		{
			name:  "too short hex",
			input: "DD_API_KEY=1234567890abcdef",
		},
		{
			name:  "non-hex characters",
			input: "DD_API_KEY=gggggggggggggggggggggggggggggggg",
		},
		{
			name:  "keyword with no value",
			input: "DD_API_KEY=",
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
