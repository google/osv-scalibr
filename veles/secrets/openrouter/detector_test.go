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

package openrouter

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	validAPIKey = "sk-or-v1-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqr"
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
		name:  "valid_openrouter_key",
		input: validAPIKey,
		want: []veles.Secret{
			APIKey{Key: validAPIKey},
		},
	}, {
		name:  "openrouter_key_in_config",
		input: "OPENROUTER_API_KEY=" + validAPIKey,
		want: []veles.Secret{
			APIKey{Key: validAPIKey},
		},
	}, {
		name:  "openrouter_key_in_env",
		input: "export OPENROUTER_KEY=\"" + validAPIKey + "\"",
		want: []veles.Secret{
			APIKey{Key: validAPIKey},
		},
	}, {
		name: "multiple_openrouter_keys",
		input: validAPIKey + "\n" +
			"sk-or-v1-zyxwvutsrqponmlkjihgfedcba0987654321zyxwvutsrqponmlkjihg",
		want: []veles.Secret{
			APIKey{Key: validAPIKey},
			APIKey{Key: "sk-or-v1-zyxwvutsrqponmlkjihgfedcba0987654321zyxwvutsrqponmlkjihg"},
		},
	}, {
		name:  "openrouter_key_with_special_chars",
		input: "sk-or-v1-test_AbC_DeF-GhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh",
		want: []veles.Secret{
			APIKey{Key: "sk-or-v1-test_AbC_DeF-GhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh"},
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
		input: "sk-or-v1-tooshort",
	}, {
		name:  "wrong_prefix",
		input: "sk-openai-abcdefghijklmnopqrstuvwxyz1234567890",
	}, {
		name:  "missing_sk_prefix",
		input: "or-v1-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqr",
	}, {
		name:  "wrong_or_format",
		input: "sk-orv1-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqr",
	}, {
		name:  "openai_key_format",
		input: "sk-proj-abcdefghij1234567890T3BlbkFJklmnopqrstuvwxyz098765432109876",
	}, {
		name:  "no_secrets",
		input: "This is just regular text with no secrets",
	}, {
		name:  "sk_prefix_but_not_key",
		input: "skeleton key is not an API key",
	}, {
		name:  "or_prefix_but_not_key",
		input: "or something else entirely",
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

func TestOpenRouterKeyValidation(t *testing.T) {
	testCases := []struct {
		name    string
		key     string
		isValid bool
	}{{
		name:    "valid_openrouter_key",
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
		name:    "openai_key_format",
		key:     "sk-proj-123456789012345678901234567890123456789012345678",
		isValid: false,
	}, {
		name:    "too_short_openrouter_key",
		key:     "sk-or-v1-short",
		isValid: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test by trying to detect the key
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
