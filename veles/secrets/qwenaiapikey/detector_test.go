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

package qwenaiapikey

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	// validAPIKey is a fake Qwen AI API key for testing (sk- + 32 lowercase hex).
	validAPIKey = "sk-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
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
		name:  "standalone_key",
		input: validAPIKey,
		want: []veles.Secret{
			APIKey{Key: validAPIKey},
		},
	}, {
		name:  "key_in_env_var",
		input: "DASHSCOPE_API_KEY=" + validAPIKey,
		want: []veles.Secret{
			APIKey{Key: validAPIKey},
		},
	}, {
		name:  "key_in_export",
		input: "export QWEN_API_KEY=\"" + validAPIKey + "\"",
		want: []veles.Secret{
			APIKey{Key: validAPIKey},
		},
	}, {
		name: "key_in_config_file",
		input: `api_key: ` + validAPIKey + `
model: qwen-turbo`,
		want: []veles.Secret{
			APIKey{Key: validAPIKey},
		},
	}, {
		name: "multiple_keys",
		input: validAPIKey + "\n" +
			"sk-00112233445566778899aabbccddeeff",
		want: []veles.Secret{
			APIKey{Key: validAPIKey},
			APIKey{Key: "sk-00112233445566778899aabbccddeeff"},
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
		input: "sk-a1b2c3d4e5f6",
	}, {
		name:  "too_long_33_chars",
		input: "sk-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e",
	}, {
		name:  "wrong_prefix",
		input: "ak-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
	}, {
		name:  "uppercase_chars_not_qwen",
		input: "sk-A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6",
	}, {
		name:  "openai_key_with_marker",
		input: "sk-proj-abcdefghij1234567890T3BlbkFJklmnopqrstuvwxyz098765432109876",
	}, {
		name:  "no_secrets",
		input: "This is just regular text with no secrets",
	}, {
		name:  "sk_prefix_but_not_key",
		input: "skeleton key is not an API key",
	}, {
		name:  "special_chars_in_key",
		input: "sk-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5_6",
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
