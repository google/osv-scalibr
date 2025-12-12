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

package pyxkeyv2_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/pyxkeyv2"
)

const (
	testKey          = `sk-pyx-2testestestestestestestestestestestestestestes`
	testKeyMixedCase = `sk-pyx-2testesTESTesTESTestestestestestestestestestes`
)

// TestDetector_truePositives tests for cases where we know the Detector
// will find a pyx v2 user key.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{pyxkeyv2.NewDetector()})
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
			pyxkeyv2.PyxKeyV2{Key: testKey},
		},
	}, {
		name:  "match at end of string",
		input: `PYX_KEY=` + testKey,
		want: []veles.Secret{
			pyxkeyv2.PyxKeyV2{Key: testKey},
		},
	}, {
		name:  "match in middle of string",
		input: `PYX_KEY="` + testKey + `"`,
		want: []veles.Secret{
			pyxkeyv2.PyxKeyV2{Key: testKey},
		},
	}, {
		name:  "matching string with mixed case",
		input: testKeyMixedCase,
		want: []veles.Secret{
			pyxkeyv2.PyxKeyV2{Key: testKeyMixedCase},
		},
	}, {
		name:  "multiple matches",
		input: testKey + testKey + testKey,
		want: []veles.Secret{
			pyxkeyv2.PyxKeyV2{Key: testKey},
			pyxkeyv2.PyxKeyV2{Key: testKey},
			pyxkeyv2.PyxKeyV2{Key: testKey},
		},
	}, {
		name:  "multiple distinct matches",
		input: testKey + "\n" + testKey[:len(testKey)-1] + "A\n",
		want: []veles.Secret{
			pyxkeyv2.PyxKeyV2{Key: testKey},
			pyxkeyv2.PyxKeyV2{Key: testKey[:len(testKey)-1] + "A"},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf(`
CONFIG_FILE=config.txt
PYX_KEY=%s
CLOUD_PROJECT=my-project
		`, testKey),
		want: []veles.Secret{
			pyxkeyv2.PyxKeyV2{Key: testKey},
		},
	}, {
		name:  "potential match longer than max key length",
		input: testKey + `test`,
		want: []veles.Secret{
			pyxkeyv2.PyxKeyV2{Key: testKey},
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
// will not find a pyx v2 user key.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{pyxkeyv2.NewDetector()})
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
		input: `SK-pyx-2testestestestestestestestestestestestestestes`,
	}, {
		name:  "number in key should not match",
		input: `sk-pyx-21estestestestestestestestestestestestesteste.`,
	}, {
		name:  "special character in key should not match",
		input: `sk-pyx-2testestestestestestestestestestestestesteste.`,
	}, {
		name:  "unexpected special character in prefix should not match",
		input: `sk.pyx-2testestestestestestestestestestestestestestes`,
	}, {
		name:  "special character after prefix should not match",
		input: `sk-pyx-2.estestestestestestestestestestestestestestes`,
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
