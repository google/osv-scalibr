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

package nugetorgapikey_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/nugetorgapikey"
	"github.com/google/osv-scalibr/veles/velestest"
)

const testKey = `oy2a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v`

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		nugetorgapikey.NewDetector(),
		testKey,
		nugetorgapikey.NuGetOrgAPIKey{Token: testKey},
		velestest.WithBackToBack(),
		velestest.WithPad('a'),
	)
}

// TestDetector_truePositives tests for cases where we know the Detector
// will find a NuGet.org API key/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{nugetorgapikey.NewDetector()})
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
			nugetorgapikey.NuGetOrgAPIKey{Token: testKey},
		},
	}, {
		name:  "match_at_end_of_string",
		input: `NUGET_API_KEY=` + testKey,
		want: []veles.Secret{
			nugetorgapikey.NuGetOrgAPIKey{Token: testKey},
		},
	}, {
		name:  "match_in_middle_of_string",
		input: `NUGET_API_KEY="` + testKey + `"`,
		want: []veles.Secret{
			nugetorgapikey.NuGetOrgAPIKey{Token: testKey},
		},
	}, {
		name:  "multiple_matches",
		input: testKey + testKey + testKey,
		want: []veles.Secret{
			nugetorgapikey.NuGetOrgAPIKey{Token: testKey},
			nugetorgapikey.NuGetOrgAPIKey{Token: testKey},
			nugetorgapikey.NuGetOrgAPIKey{Token: testKey},
		},
	}, {
		name:  "multiple_distinct_matches",
		input: testKey + "\n" + testKey[:len(testKey)-1] + "w",
		want: []veles.Secret{
			nugetorgapikey.NuGetOrgAPIKey{Token: testKey},
			nugetorgapikey.NuGetOrgAPIKey{Token: testKey[:len(testKey)-1] + "w"},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf(`
:nuget_api_key: nuget-test
:NUGET_API_KEY: %s
		`, testKey),
		want: []veles.Secret{
			nugetorgapikey.NuGetOrgAPIKey{Token: testKey},
		},
	}, {
		name:  "potential_match_longer_than_max_key_length",
		input: testKey + `extra`,
		want: []veles.Secret{
			nugetorgapikey.NuGetOrgAPIKey{Token: testKey},
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
// will not find a NuGet.org API key.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{nugetorgapikey.NewDetector()})
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
		input: `oy2!@#$%^&*()_+{}[]|:;<>?,./~` + `1234567890123`,
	}, {
		name:  "incorrect_prefix_should_not_match",
		input: `oy3a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v`,
	}, {
		name:  "prefix_missing_should_not_match",
		input: `a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3`,
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
