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

package anthropicapikey_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/anthropicapikey"
)

const (
	testKey          = `sk-ant-api03-test123456789012345678901234567890123456789012345678ABC`
	testKeyMixedCase = `sk-ant-api03-TEST123456789012345678901234567890123456789012345678ABC`
)

// TestDetector_truePositives tests for cases where we know the Detector
// will find an Anthropic API key/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{anthropicapikey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	// The regex matches "sk-ant-" + version identifier + "-" + alphanumeric characters and hyphens
	expectedKey := testKey
	expectedKeyMixedCase := testKeyMixedCase

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple_matching_string",
		input: testKey,
		want: []veles.Secret{
			anthropicapikey.AnthropicAPIKey{Key: expectedKey},
		},
	}, {
		name:  "match_at_end_of_string",
		input: `ANTHROPIC_API_KEY=` + testKey,
		want: []veles.Secret{
			anthropicapikey.AnthropicAPIKey{Key: expectedKey},
		},
	}, {
		name:  "match_in_middle_of_string",
		input: `ANTHROPIC_API_KEY="` + testKey + `"`,
		want: []veles.Secret{
			anthropicapikey.AnthropicAPIKey{Key: expectedKey},
		},
	}, {
		name:  "matching_string_with_mixed_case",
		input: testKeyMixedCase,
		want: []veles.Secret{
			anthropicapikey.AnthropicAPIKey{Key: expectedKeyMixedCase},
		},
	}, {
		name:  "multiple_matches",
		input: testKey + " " + testKey + " " + testKey,
		want: []veles.Secret{
			anthropicapikey.AnthropicAPIKey{Key: expectedKey},
			anthropicapikey.AnthropicAPIKey{Key: expectedKey},
			anthropicapikey.AnthropicAPIKey{Key: expectedKey},
		},
	}, {
		name:  "multiple_distinct_matches",
		input: testKey + "\n" + testKey[:len(testKey)-1] + "Z\n",
		want: []veles.Secret{
			anthropicapikey.AnthropicAPIKey{Key: expectedKey},
			anthropicapikey.AnthropicAPIKey{Key: testKey[:len(testKey)-1] + "Z"},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf(`
CONFIG_FILE=config.txt
ANTHROPIC_API_KEY=%s
CLOUD_PROJECT=my-project
		`, testKey),
		want: []veles.Secret{
			anthropicapikey.AnthropicAPIKey{Key: expectedKey},
		},
	}, {
		name:  "potential_match_longer_than_max_key_length",
		input: testKey + ` test`,
		want: []veles.Secret{
			anthropicapikey.AnthropicAPIKey{Key: expectedKey},
		},
	}, {
		name:  "different_version_identifiers",
		input: `sk-ant-api04-test123 sk-ant-v2-test456 sk-ant-beta1-test789`,
		want: []veles.Secret{
			anthropicapikey.AnthropicAPIKey{Key: "sk-ant-api04-test123"},
			anthropicapikey.AnthropicAPIKey{Key: "sk-ant-v2-test456"},
			anthropicapikey.AnthropicAPIKey{Key: "sk-ant-beta1-test789"},
		},
	}, {
		name:  "admin_key_with_underscores",
		input: `sk-ant-admin01-test_key_with_underscores_and-hyphens`,
		want: []veles.Secret{
			anthropicapikey.AnthropicAPIKey{Key: "sk-ant-admin01-test_key_with_underscores_and-hyphens"},
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
// will not find an Anthropic API key.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{anthropicapikey.NewDetector()})
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
		name:  "wrong_prefix_should_not_match",
		input: `sk-openai-api03-test123456789012345678901234567890123456789`,
	}, {
		name:  "missing_version_delimiter_should_not_match",
		input: `sk-ant-test123456789012345678901234567890123456789`,
	}, {
		name:  "special_character_in_prefix_should_not_match",
		input: `sk.ant-api03-test123456789012345678901234567890123456789`,
	}, {
		name:  "too_short_suffix_should_not_match",
		input: `sk-ant-api03-`,
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
