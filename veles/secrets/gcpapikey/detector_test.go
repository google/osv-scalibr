// Copyright 2025 Google LLC
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

package gcpapikey_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gcpapikey"
)

const (
	testKey          = `AIzatestestestestestestestestestesttest`
	testKeyMixedCase = `AIzaTESTesTESTesTESTesTESTesTESTestTEST`
)

// TestDetector_truePositives tests for cases where we know the Detector
// will find a GCP API key/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{gcpapikey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: testKey,
		want: []veles.Secret{
			gcpapikey.GCPAPIKey{Key: testKey},
		},
	}, {
		name:  "match at end of string",
		input: `API_KEY=` + testKey,
		want: []veles.Secret{
			gcpapikey.GCPAPIKey{Key: testKey},
		},
	}, {
		name:  "match in middle of string",
		input: `API_KEY="` + testKey + `"`,
		want: []veles.Secret{
			gcpapikey.GCPAPIKey{Key: testKey},
		},
	}, {
		name:  "matching string with mixed case",
		input: testKeyMixedCase,
		want: []veles.Secret{
			gcpapikey.GCPAPIKey{Key: testKeyMixedCase},
		},
	}, {
		name:  "multiple matches",
		input: testKey + testKey + testKey,
		want: []veles.Secret{
			gcpapikey.GCPAPIKey{Key: testKey},
			gcpapikey.GCPAPIKey{Key: testKey},
			gcpapikey.GCPAPIKey{Key: testKey},
		},
	}, {
		name:  "multiple distinct matches",
		input: testKey + "\n" + testKey[:len(testKey)-1] + "1\n",
		want: []veles.Secret{
			gcpapikey.GCPAPIKey{Key: testKey},
			gcpapikey.GCPAPIKey{Key: testKey[:len(testKey)-1] + "1"},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf(`
CONFIG_FILE=config.txt
API_KEY=%s
CLOUD_PROJECT=my-project
		`, testKey),
		want: []veles.Secret{
			gcpapikey.GCPAPIKey{Key: testKey},
		},
	}, {
		name:  "potential match longer than max key length",
		input: testKey + `test`,
		want: []veles.Secret{
			gcpapikey.GCPAPIKey{Key: testKey},
		},
	}}
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

// TestDetector_trueNegatives tests for cases where we know the Detector
// will not find a GCP API key.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{gcpapikey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "empty input",
		input: "",
	}, {
		name:  "short key should not match",
		input: testKey[:len(testKey)-1],
	}, {
		name:  "incorrect casing of prefix should not match",
		input: `aizatestestestestestestestestestesttest`,
	}, {
		name:  "special character in key should not match",
		input: `AIzatestestestestestestestestestesttes.`,
	}, {
		name:  "special character in prefix should not match",
		input: `AI.zatestestestestestestestestestesttes`,
	}, {
		name:  "special character after prefix should not match",
		input: `AIza.testestestestestestestestestesttes`,
	}, {
		// See https://pkg.go.dev/regexp and
		// https://github.com/google/re2/wiki/syntax.
		name:  "overlapping matches are not supported",
		input: `AIza` + testKey,
		want: []veles.Secret{
			gcpapikey.GCPAPIKey{Key: `AIza` + testKey[:len(testKey)-4]},
		},
	}}
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
