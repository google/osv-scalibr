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

package nugetapikey_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	nugetapikey "github.com/google/osv-scalibr/veles/secrets/nugetapikey"
)

const (
	// Example valid NuGet API key (46 characters starting with oy2).
	detectorNuGetKey = "oy2nshvzu4qqwr7gglwqk3ndyyjrlf2e3krcuamdpgjtlm"
)

// TestDetector_truePositives tests NuGet API key detection.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{
		nugetapikey.NewDetector(),
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple_matching_string",
		input: detectorNuGetKey,
		want: []veles.Secret{
			nugetapikey.NuGetAPIKey{Key: detectorNuGetKey},
		},
	}, {
		name:  "match_at_end_of_string",
		input: `NUGET_API_KEY=` + detectorNuGetKey,
		want: []veles.Secret{
			nugetapikey.NuGetAPIKey{Key: detectorNuGetKey},
		},
	}, {
		name:  "match_in_quotes",
		input: `key="` + detectorNuGetKey + `"`,
		want: []veles.Secret{
			nugetapikey.NuGetAPIKey{Key: detectorNuGetKey},
		},
	}, {
		name:  "multiple_matches",
		input: detectorNuGetKey + "\n" + detectorNuGetKey,
		want: []veles.Secret{
			nugetapikey.NuGetAPIKey{Key: detectorNuGetKey},
			nugetapikey.NuGetAPIKey{Key: detectorNuGetKey},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf("config:\n  api_key: %s\n",
			detectorNuGetKey),
		want: []veles.Secret{
			nugetapikey.NuGetAPIKey{Key: detectorNuGetKey},
		},
	}, {
		name:  "potential_match_longer_than_max_key_length",
		input: detectorNuGetKey + "EXTRA",
		want: []veles.Secret{
			nugetapikey.NuGetAPIKey{Key: detectorNuGetKey},
		},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(),
				strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got,
				cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s",
					diff)
			}
		})
	}
}

// TestDetector_trueNegatives tests NuGet API key false negatives.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{
		nugetapikey.NewDetector(),
	})
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
		input: detectorNuGetKey[:len(detectorNuGetKey)-5],
	}, {
		name:  "invalid_character_in_key_should_not_match",
		input: strings.ReplaceAll(detectorNuGetKey, "a", "A"),
	}, {
		name:  "special_character_in_key_should_not_match",
		input: strings.ReplaceAll(detectorNuGetKey, "a", "-"),
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(),
				strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got,
				cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s",
					diff)
			}
		})
	}
}
