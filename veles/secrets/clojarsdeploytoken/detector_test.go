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

package clojarsdeploytoken_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/clojarsdeploytoken"
	"github.com/google/osv-scalibr/veles/velestest"
)

const testKey = `CLOJARS_abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456`

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		clojarsdeploytoken.NewDetector(),
		testKey,
		clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
		velestest.WithBackToBack(),
		velestest.WithPad('z'),
	)
}

// TestDetector_truePositives tests for cases where we know the Detector
// will find a Clojars deploy token/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{clojarsdeploytoken.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple_matching_string",
		input: testKey,
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
		},
	}, {
		name:  "match_at_end_of_string",
		input: `CLOJARS_TOKEN=` + testKey,
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
		},
	}, {
		name:  "match_in_middle_of_string",
		input: `CLOJARS_TOKEN="` + testKey + `"`,
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
		},
	}, {
		name:  "multiple_matches",
		input: testKey + " " + testKey + " " + testKey,
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
		},
	}, {
		name:  "multiple_distinct_matches",
		input: testKey + "\n" + testKey[:len(testKey)-1] + "a",
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey[:len(testKey)-1] + "a"},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf(`
:clojars_deploy_token: clojars-test
:CLOJARS_TOKEN: %s
		`, testKey),
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
		},
	}, {
		name:  "potential_match_longer_than_max_key_length",
		input: testKey + `extra`,
		want: []veles.Secret{
			clojarsdeploytoken.ClojarsDeployToken{Token: testKey},
		},
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			fmt.Printf("got = %+v\n", got)
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDetector_trueNegatives tests for cases where we know the Detector
// will not find a Clojars deploy token.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{clojarsdeploytoken.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "empty_input",
		input: "",
	}, {
		name:  "short_key_should_not_match",
		input: testKey[:len(testKey)-1],
	}, {
		name:  "invalid_character_in_key_should_not_match",
		input: `CLOJARS_` + `GHIJKL1234567890GHIJKL1234567890GHIJKL1234567890GHIJKL123456`,
	}, {
		name:  "incorrect_prefix_should_not_match",
		input: `CLOJARZ_abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456`,
	}, {
		name:  "prefix_missing_should_not_match",
		input: `abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456`,
	}, {
		name:  "uppercase_hex_should_not_match",
		input: `CLOJARS_ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF123456`,
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
