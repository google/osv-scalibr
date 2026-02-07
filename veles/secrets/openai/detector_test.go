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

package openai

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	validAPIKey = "sk-proj-12345678901234567890T3BlbkFJ12345678901234567890123456"
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
		name:  "project_key",
		input: validAPIKey,
		want: []veles.Secret{
			APIKey{Key: validAPIKey},
		},
	}, {
		name:  "project_key_in_config",
		input: "OPENAI_API_KEY=" + validAPIKey,
		want: []veles.Secret{
			APIKey{Key: validAPIKey},
		},
	}, {
		name:  "project_key_in_env",
		input: "export OPENAI_KEY=\"" + validAPIKey + "\"",
		want: []veles.Secret{
			APIKey{Key: validAPIKey},
		},
	}, {
		name: "multiple_project_keys",
		input: validAPIKey + "\n" +
			"sk-proj-abcdefghij1234567890T3BlbkFJklmnopqrstuvwxyz098765432109876",
		want: []veles.Secret{
			APIKey{Key: validAPIKey},
			APIKey{Key: "sk-proj-abcdefghij1234567890T3BlbkFJ" +
				"klmnopqrstuvwxyz098765432109876"},
		},
	}, {
		name: "openai_project_key_with_special_chars",
		input: "sk-proj-AbC_DeF-GhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh" +
			"T3BlbkFJXyZ-123_456-789_012-345_678-901_234-567_890-AbCdEfGhIjKlMnOpQrStUvWxYzZzZz",
		want: []veles.Secret{
			APIKey{Key: "sk-proj-AbC_DeF-GhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh" +
				"T3BlbkFJXyZ-123_456-789_012-345_678-901_234-567_890-AbCdEfGhIjKlMnOpQrStUvWxYzZzZz"},
		},
	}, {
		name:  "legacy_openai_key_format",
		input: "sk-FakeTest123456789T3BlbkFJAbCdEfGhIjKlMnOpQrStUvWxYz",
		want: []veles.Secret{
			APIKey{Key: "sk-FakeTest123456789T3BlbkFJAbCdEfGhIjKlMnOpQrStUvWxYz"},
		},
	}, {
		name: "multiple_legacy_keys",
		input: "sk-TestKey1234567890T3BlbkFJXyZaBcDeFgHiJkLmNoPqRsTuVw\n" +
			"sk-AnotherFakeKey12T3BlbkFJMnOpQrStUvWxYzAbCdEfGhIjKl",
		want: []veles.Secret{
			APIKey{Key: "sk-TestKey1234567890T3BlbkFJXyZaBcDeFgHiJkLmNoPqRsTuVw"},
			APIKey{Key: "sk-AnotherFakeKey12T3BlbkFJMnOpQrStUvWxYzAbCdEfGhIjKl"},
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
		input: "sk-tooshort",
	}, {
		name:  "wrong_prefix",
		input: "ak-proj-abcdefghijklmnopqrstT3BlbkFJuvwxyzABCDEF123456",
	}, {
		name:  "malformed_project_key_missing_marker",
		input: "sk-proj-abcdefghijklmnopqrstuvwxyzABCDEF123456",
	}, {
		name:  "malformed_project_key_wrong_marker",
		input: "sk-proj-abcdefghijklmnopqrT3BlbkFZuvwxyzABCDEF123456",
	}, {
		name:  "legacy_key_not_supported",
		input: "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJK",
	}, {
		name:  "no_secrets",
		input: "This is just regular text with no secrets",
	}, {
		name:  "sk_prefix_but_not_key",
		input: "skeleton key is not an API key",
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

func TestProjectKeyValidation(t *testing.T) {
	testCases := []struct {
		name    string
		key     string
		isValid bool
	}{{
		name:    "valid_project_key",
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
		name:    "legacy_key_format",
		key:     "sk-123456789012345678901234567890123456789012345678",
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
