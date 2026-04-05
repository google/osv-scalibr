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

package databrickspat_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/databrickspat"
	"github.com/google/osv-scalibr/veles/velestest"
)

const testKey = `dapi1234567890abcdef1234567890abcdef`

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		databrickspat.NewDetector(),
		testKey,
		databrickspat.DatabricksPAT{Token: testKey},
		velestest.WithBackToBack(),
		velestest.WithPad('a'),
	)
}

// TestDetector_truePositives tests for cases where we know the Detector
// will find a Databricks Personal Access Token/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{databrickspat.NewDetector()})
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
			databrickspat.DatabricksPAT{Token: testKey},
		},
	}, {
		name:  "match_at_end_of_string",
		input: `DATABRICKS_TOKEN=` + testKey,
		want: []veles.Secret{
			databrickspat.DatabricksPAT{Token: testKey},
		},
	}, {
		name:  "match_in_middle_of_string",
		input: `DATABRICKS_TOKEN="` + testKey + `"`,
		want: []veles.Secret{
			databrickspat.DatabricksPAT{Token: testKey},
		},
	}, {
		name:  "multiple_matches",
		input: testKey + testKey + testKey,
		want: []veles.Secret{
			databrickspat.DatabricksPAT{Token: testKey},
			databrickspat.DatabricksPAT{Token: testKey},
			databrickspat.DatabricksPAT{Token: testKey},
		},
	}, {
		name:  "multiple_distinct_matches",
		input: testKey + "\n" + testKey[:len(testKey)-1] + "a",
		want: []veles.Secret{
			databrickspat.DatabricksPAT{Token: testKey},
			databrickspat.DatabricksPAT{Token: testKey[:len(testKey)-1] + "a"},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf(`
:databricks_token: databricks-test
:DATABRICKS_TOKEN: %s
		`, testKey),
		want: []veles.Secret{
			databrickspat.DatabricksPAT{Token: testKey},
		},
	}, {
		name:  "potential_match_longer_than_max_key_length",
		input: testKey + `extra`,
		want: []veles.Secret{
			databrickspat.DatabricksPAT{Token: testKey},
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
// will not find a Databricks Personal Access Token.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{databrickspat.NewDetector()})
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
		input: "dapi1234567890abcdef1234567890abcde",
	}, {
		name:  "invalid_character_in_key_should_not_match",
		input: `dapi!@#$%^&*()_+{}[]|:;<>?,./~123456`,
	}, {
		name:  "incorrect_prefix_should_not_match",
		input: `dapy1234567890abcdef1234567890abcdef`,
	}, {
		name:  "prefix_missing_should_not_match",
		input: `1234567890abcdef1234567890abcdef`,
	}, {
		name:  "uppercase_hex_should_not_match",
		input: `dapi1234567890ABCDEF1234567890ABCDEF`,
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
