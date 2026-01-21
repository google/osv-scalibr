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

package packagist_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/packagist"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	// Test API Key with 28 hex chars (minimum based on actual format)
	testAPIKeyMin = "packagist_ack_aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// Test API Key with 32 hex chars (maximum based on actual format)
	testAPIKeyMax = "packagist_ack_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	// Test API Key with 28 hex chars (realistic example)
	testAPIKeyMid = "packagist_ack_7432cdc05ea3f83037723ff56638"

	// Test API Secret with 64 hex chars (minimum)
	testAPISecretMin = "packagist_acs_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	// Test API Secret with 96 hex chars (maximum)
	testAPISecretMax = "packagist_acs_dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	// Test API Secret with 80 hex chars (realistic example)
	testAPISecretMid = "packagist_acs_d3caf3a8039266d1b93cc91352d1571b24e39b14e0feb4e7fc1c73c3e8417e60d99c18bd"
)

func TestAPIKeyDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		packagist.NewAPIKeyDetector(),
		testAPIKeyMid,
		packagist.APIKey{Key: testAPIKeyMid},
		velestest.WithBackToBack(),
		velestest.WithPad('z'),
	)
}

func TestAPISecretDetectorAcceptance(t *testing.T) {
	// Since NewAPISecretDetector now uses pair detection, we need both key and secret
	input := testAPIKeyMid + " " + testAPISecretMid
	velestest.AcceptDetector(
		t,
		packagist.NewAPISecretDetector(),
		input,
		packagist.APISecret{Secret: testAPISecretMid, Key: testAPIKeyMid},
		// Note: WithBackToBack() is not used because pair detection has different behavior
		// for back-to-back patterns (it may match multiple pairs differently)
		velestest.WithPad('z'),
	)
}

// TestAPIKeyDetector_TruePositives tests for cases where we know the APIKeyDetector
// will find Packagist API Key/s.
func TestAPIKeyDetector_TruePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{packagist.NewAPIKeyDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple_matching_string_min",
		input: testAPIKeyMin,
		want: []veles.Secret{
			packagist.APIKey{Key: testAPIKeyMin},
		},
	}, {
		name:  "simple_matching_string_max",
		input: testAPIKeyMax,
		want: []veles.Secret{
			packagist.APIKey{Key: testAPIKeyMax},
		},
	}, {
		name:  "match_at_end_of_string",
		input: `PACKAGIST_API_KEY=` + testAPIKeyMid,
		want: []veles.Secret{
			packagist.APIKey{Key: testAPIKeyMid},
		},
	}, {
		name:  "match_in_middle_of_string",
		input: `PACKAGIST_API_KEY="` + testAPIKeyMid + `"`,
		want: []veles.Secret{
			packagist.APIKey{Key: testAPIKeyMid},
		},
	}, {
		name:  "multiple_matches",
		input: testAPIKeyMin + " " + testAPIKeyMax,
		want: []veles.Secret{
			packagist.APIKey{Key: testAPIKeyMin},
			packagist.APIKey{Key: testAPIKeyMax},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf(`
:test_api_key: packagist_ack_invalid
:packagist_api_key: %s 
		`, testAPIKeyMid),
		want: []veles.Secret{
			packagist.APIKey{Key: testAPIKeyMid},
		},
	}, {
		name:  "potential_match_with_extra_characters",
		input: testAPIKeyMid + `_extra`,
		want: []veles.Secret{
			packagist.APIKey{Key: testAPIKeyMid},
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

// TestAPIKeyDetector_TrueNegatives tests for cases where we know the APIKeyDetector
// will not find a Packagist API Key.
func TestAPIKeyDetector_TrueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{packagist.NewAPIKeyDetector()})
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
		name:  "wrong_prefix",
		input: `packagist_acs_aaaaaaaaaaaaaaaaaaaaaaaaaaaa`,
	}, {
		name:  "too_short",
		input: `packagist_ack_aaaaaaaaaaaaaaaaaaaaaaaaa`, // 27 chars, need 28+
	}, {
		name:  "invalid_characters_uppercase",
		input: `packagist_ack_AAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
	}, {
		name:  "invalid_characters_special",
		input: `packagist_ack_!!!!!!!!!!!!!!!!!!!!!!!!!!!!`,
	}, {
		name:  "missing_underscore",
		input: `packagistackaaaaaaaaaaaaaaaaaaaaaaaaaaaa`,
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

// TestAPISecretDetector_TruePositives tests for cases where we know the APISecretDetector
// will find Packagist API Secret/s (when paired with keys).
func TestAPISecretDetector_TruePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{packagist.NewAPISecretDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple_matching_pair_min",
		input: testAPIKeyMin + " " + testAPISecretMin,
		want: []veles.Secret{
			packagist.APISecret{Secret: testAPISecretMin, Key: testAPIKeyMin},
		},
	}, {
		name:  "simple_matching_pair_max",
		input: testAPIKeyMax + " " + testAPISecretMax,
		want: []veles.Secret{
			packagist.APISecret{Secret: testAPISecretMax, Key: testAPIKeyMax},
		},
	}, {
		name:  "pair_at_end_of_string",
		input: `PACKAGIST_API_KEY=` + testAPIKeyMid + ` PACKAGIST_API_SECRET=` + testAPISecretMid,
		want: []veles.Secret{
			packagist.APISecret{Secret: testAPISecretMid, Key: testAPIKeyMid},
		},
	}, {
		name:  "pair_in_middle_of_string",
		input: `config: "PACKAGIST_API_KEY=` + testAPIKeyMid + ` PACKAGIST_API_SECRET=` + testAPISecretMid + `"`,
		want: []veles.Secret{
			packagist.APISecret{Secret: testAPISecretMid, Key: testAPIKeyMid},
		},
	}, {
		name:  "multiple_pairs",
		input: testAPIKeyMin + " " + testAPISecretMin + " " + testAPIKeyMax + " " + testAPISecretMax,
		want: []veles.Secret{
			packagist.APISecret{Secret: testAPISecretMin, Key: testAPIKeyMin},
			packagist.APISecret{Secret: testAPISecretMax, Key: testAPIKeyMax},
		},
	}, {
		name: "larger_input_containing_pair",
		input: fmt.Sprintf(`
:test_api_key: packagist_ack_invalid
:packagist_api_key: %s 
:packagist_api_secret: %s
		`, testAPIKeyMid, testAPISecretMid),
		want: []veles.Secret{
			packagist.APISecret{Secret: testAPISecretMid, Key: testAPIKeyMid},
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

// TestAPISecretDetector_TrueNegatives tests for cases where we know the APISecretDetector
// will not find a Packagist API Secret (when key is missing or format is invalid).
func TestAPISecretDetector_TrueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{packagist.NewAPISecretDetector()})
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
		name:  "only_secret_no_key",
		input: testAPISecretMid, // Pair detector requires both
	}, {
		name:  "only_key_no_secret",
		input: testAPIKeyMid, // Pair detector requires both
	}, {
		name:  "wrong_prefix",
		input: testAPIKeyMid + " packagist_ack_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}, {
		name:  "secret_too_short",
		input: testAPIKeyMid + " packagist_acs_ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", // 63 chars, need 64+
	}, {
		name:  "invalid_characters_uppercase",
		input: testAPIKeyMid + " packagist_acs_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
	}, {
		name:  "invalid_characters_special",
		input: testAPIKeyMid + " packagist_acs_@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
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

// TestAPISecretDetector_BothFound tests that when both key and secret are found together,
// the detector creates a APISecret with the Key field populated.
func TestAPISecretDetector_BothFound(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{packagist.NewAPISecretDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "key_and_secret_on_same_line",
		input: testAPIKeyMid + " " + testAPISecretMid,
		want: []veles.Secret{
			packagist.APISecret{
				Secret: testAPISecretMid,
				Key:    testAPIKeyMid,
			},
		},
	}, {
		name: "key_and_secret_on_different_lines",
		input: fmt.Sprintf(`PACKAGIST_API_KEY=%s
PACKAGIST_API_SECRET=%s`, testAPIKeyMid, testAPISecretMid),
		want: []veles.Secret{
			packagist.APISecret{
				Secret: testAPISecretMid,
				Key:    testAPIKeyMid,
			},
		},
	}, {
		name: "multiple_pairs",
		input: fmt.Sprintf(`%s %s
%s %s`, testAPIKeyMin, testAPISecretMin, testAPIKeyMax, testAPISecretMax),
		want: []veles.Secret{
			packagist.APISecret{
				Secret: testAPISecretMin,
				Key:    testAPIKeyMin,
			},
			packagist.APISecret{
				Secret: testAPISecretMax,
				Key:    testAPIKeyMax,
			},
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

// TestAPISecretDetector_OnlySecret tests that when only the secret is found,
// the pair detector does not match (it requires both).
func TestAPISecretDetector_OnlySecret(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{packagist.NewAPISecretDetector()})
	if err != nil {
		t.Fatal(err)
	}

	// When only secret is present, pair detector should not match
	input := testAPISecretMid
	got, err := engine.Detect(t.Context(), strings.NewReader(input))
	if err != nil {
		t.Errorf("Detect() error: %v, want nil", err)
	}
	if len(got) != 0 {
		t.Errorf("Detect() found %d secrets, want 0 (pair detector requires both key and secret)", len(got))
	}
}

// TestAPISecretDetector_OnlyKey tests that when only the key is found,
// the pair detector does not match (it requires both).
func TestAPISecretDetector_OnlyKey(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{packagist.NewAPISecretDetector()})
	if err != nil {
		t.Fatal(err)
	}

	// When only key is present, pair detector should not match
	input := testAPIKeyMid
	got, err := engine.Detect(t.Context(), strings.NewReader(input))
	if err != nil {
		t.Errorf("Detect() error: %v, want nil", err)
	}
	if len(got) != 0 {
		t.Errorf("Detect() found %d secrets, want 0 (pair detector requires both key and secret)", len(got))
	}
}

// TestAllDetectors_Combined tests that when both detectors are used together,
// we get the expected combination of results.
func TestAllDetectors_Combined(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{
		packagist.NewAPIKeyDetector(),
		packagist.NewAPISecretDetector(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Input with both key and secret
	input := fmt.Sprintf(`PACKAGIST_API_KEY=%s
PACKAGIST_API_SECRET=%s`, testAPIKeyMid, testAPISecretMid)

	got, err := engine.Detect(t.Context(), strings.NewReader(input))
	if err != nil {
		t.Errorf("Detect() error: %v, want nil", err)
	}

	// We expect 2 secrets:
	// 1. APIKey from NewAPIKeyDetector
	// 2. APISecret (Key=testAPIKeyMid) from NewAPISecretDetector
	want := []veles.Secret{
		packagist.APIKey{Key: testAPIKeyMid},
		packagist.APISecret{Secret: testAPISecretMid, Key: testAPIKeyMid},
	}

	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("Detect() diff (-want +got):\n%s", diff)
	}
}
