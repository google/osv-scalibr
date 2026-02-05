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

package herokuplatformkey_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	herokuplatformkey "github.com/google/osv-scalibr/veles/secrets/herokuplatformkey"
)

var (
	// Example valid Heroku Platform API key.
	detectorKey = "HRKU-AALJCYR7SRzPkj9_BGqhi1jAI1J5P4WfD6ITENvdVydAPCnNcAlrMMahHrTo"
)

// TestSecretKeyDetector_truePositives tests Key detection.
func TestSecretKeyDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{herokuplatformkey.NewSecretKeyDetector()},
	)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple_matching_string",
		input: detectorKey,
		want: []veles.Secret{
			herokuplatformkey.HerokuSecret{Key: detectorKey},
		},
	}, {
		name:  "match_at_end_of_string",
		input: `HEROKU_KEY=` + detectorKey,
		want: []veles.Secret{
			herokuplatformkey.HerokuSecret{Key: detectorKey},
		},
	}, {
		name:  "match_in_quotes",
		input: `key="` + detectorKey + `"`,
		want: []veles.Secret{
			herokuplatformkey.HerokuSecret{Key: detectorKey},
		},
	}, {
		name:  "multiple_matches",
		input: detectorKey + "\n" + detectorKey,
		want: []veles.Secret{
			herokuplatformkey.HerokuSecret{Key: detectorKey},
			herokuplatformkey.HerokuSecret{Key: detectorKey},
		},
	}, {
		name: "multiple_lined_input_containing_key",
		input: fmt.Sprintf("config:\n\n\n  api_key: %s\n",
			detectorKey),
		want: []veles.Secret{
			herokuplatformkey.HerokuSecret{Key: detectorKey},
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

// TestSecretKeyDetector_trueNegatives tests Key false negatives.
func TestSecretKeyDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{herokuplatformkey.NewSecretKeyDetector()},
	)
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
		input: "HRKU-AA",
	}, {
		name:  "invalid_character_in_key_should_not_match",
		input: "HRKU-AALJCYR7SRzPkj9_BGqhi1jAI1J5P4WfD6*TENvdVydAPCnNcAlrMMahHrTo",
	}, {
		name:  "incorrect_prefix_should_not_match",
		input: "TRKU-AALJCYR7SRzPkj9_BGqhi1jAI1J5P4WfD6ITENvdVydAPCnNcAlrMMahHrTo",
	}, {
		name:  "prefix_missing_hyphen_should_not_match",
		input: "HRKU_AALJCYR7SRzPkj9_BGqhi1jAI1J5P4WfD6ITENvdVydAPCnNcAlrMMahHrTo", // removes the underscore
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
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
