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

package cursorapikey

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	validAPIKey = "key_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		NewDetector(),
		validAPIKey,
		APIKey{Key: validAPIKey},
	)
}

func TestDetector(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "valid_cursor_key",
		input: validAPIKey,
		want: []veles.Secret{
			APIKey{Key: validAPIKey},
		},
	}, {
		name:  "cursor_key_in_config",
		input: "CURSOR_API_KEY=" + validAPIKey,
		want: []veles.Secret{
			APIKey{Key: validAPIKey},
		},
	}, {
		name:  "cursor_key_in_env",
		input: "export CURSOR_KEY=\"" + validAPIKey + "\"",
		want: []veles.Secret{
			APIKey{Key: validAPIKey},
		},
	}, {
		name: "multiple_cursor_keys",
		input: validAPIKey + "\n" +
			"key_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		want: []veles.Secret{
			APIKey{Key: validAPIKey},
			APIKey{Key: "key_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		},
	}, {
		name:  "cursor_key_with_all_lowercase_and_digits",
		input: "key_abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01",
		want: []veles.Secret{
			APIKey{Key: "key_abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01"},
		},
	}, {
		name:  "cursor_key_in_json",
		input: `{"api_key":"` + validAPIKey + `"}`,
		want: []veles.Secret{
			APIKey{Key: validAPIKey},
		},
	}, {
		name:  "cursor_key_in_yaml",
		input: "api_key: " + validAPIKey,
		want: []veles.Secret{
			APIKey{Key: validAPIKey},
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

func TestDetector_NoMatches(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
	}{{
		name:  "too_short",
		input: "key_tooshort",
	}, {
		name:  "wrong_prefix",
		input: "api_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
	}, {
		name:  "uppercase_letters",
		input: "key_ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
	}, {
		name:  "contains_special_chars",
		input: "key_abcdef0123456789abcdef0123456789abcdef0123456789abcdef_1234567",
	}, {
		name:  "contains_underscore_in_body",
		input: "key_abcdef0123456789_bcdef0123456789abcdef0123456789abcdef0123456789",
	}, {
		name:  "contains_hyphen",
		input: "key_abcdef0123456789-bcdef0123456789abcdef0123456789abcdef0123456789",
	}, {
		name:  "no_secrets",
		input: "This is just regular text with no secrets",
	}, {
		name:  "key_prefix_but_not_api_key",
		input: "keyboard shortcuts are not API keys",
	}, {
		name:  "key_in_middle_of_word_should_not_match",
		input: "mykey_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
	}, {
		name:  "63_chars_after_prefix",
		input: "key_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456",
	}, {
		name:  "65_chars_after_prefix",
		input: "key_abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345678",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if len(got) != 0 {
				t.Errorf("Detect() got %v secrets, want 0", len(got))
			}
		})
	}
}

func TestKeyValidation(t *testing.T) {
	testCases := []struct {
		name    string
		key     string
		isValid bool
	}{{
		name:    "valid_cursor_key",
		key:     validAPIKey,
		isValid: true,
	}, {
		name:    "not_a_key",
		key:     "not-a-key",
		isValid: false,
	}, {
		name:    "empty_string",
		key:     "",
		isValid: false,
	}, {
		name:    "wrong_prefix",
		key:     "api_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		isValid: false,
	}, {
		name:    "uppercase_in_key",
		key:     "key_ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		isValid: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			engine, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
			if err != nil {
				t.Fatal(err)
			}

			got, err := engine.Detect(t.Context(), strings.NewReader(tc.key))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}

			isDetected := len(got) > 0
			if isDetected != tc.isValid {
				t.Errorf("Key %q detected=%v, want valid=%v",
					tc.key, isDetected, tc.isValid)
			}
		})
	}
}
