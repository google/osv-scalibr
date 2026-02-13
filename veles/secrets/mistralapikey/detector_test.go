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

package mistralapikey_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/mistralapikey"
	"github.com/google/osv-scalibr/veles/velestest"
)

// testKey is a fake 32-character alphanumeric Mistral API key for testing.
const testKey = "abcdefghij1234567890ABCDEFGHIJ12"

func TestAcceptDetector(t *testing.T) {
	velestest.AcceptDetector(
		t,
		mistralapikey.NewDetector(),
		"mistral "+testKey,
		mistralapikey.MistralAPIKey{Key: testKey},
	)
}

// TestDetector_truePositives tests for cases where we know the Detector
// will find a Mistral API key.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{mistralapikey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "env_var_style_uppercase",
		input: "MISTRAL_API_KEY=" + testKey,
		want:  []veles.Secret{mistralapikey.MistralAPIKey{Key: testKey}},
	}, {
		name:  "env_var_style_lowercase",
		input: "mistral_api_key=" + testKey,
		want:  []veles.Secret{mistralapikey.MistralAPIKey{Key: testKey}},
	}, {
		name:  "context_mistralai",
		input: "mistralai: " + testKey,
		want:  []veles.Secret{mistralapikey.MistralAPIKey{Key: testKey}},
	}, {
		name:  "context_api_mistral_ai_url",
		input: "api.mistral.ai/v1/models " + testKey,
		want:  []veles.Secret{mistralapikey.MistralAPIKey{Key: testKey}},
	}, {
		name:  "context_word_mistral",
		input: "mistral " + testKey,
		want:  []veles.Secret{mistralapikey.MistralAPIKey{Key: testKey}},
	}, {
		name: "json_config_style",
		input: fmt.Sprintf(`{
			"mistral": {
				"api_key": "%s"
			}
		}`, testKey),
		want: []veles.Secret{mistralapikey.MistralAPIKey{Key: testKey}},
	}, {
		name:  "key_before_context",
		input: testKey + " mistral",
		want:  []veles.Secret{mistralapikey.MistralAPIKey{Key: testKey}},
	}, {
		name:  "multiple_keys_different_contexts",
		input: "mistral " + testKey + " mistralai " + testKey,
		want: []veles.Secret{
			mistralapikey.MistralAPIKey{Key: testKey},
			mistralapikey.MistralAPIKey{Key: testKey},
		},
	}, {
		name:  "context_in_quotes",
		input: `"mistral_api_key": "` + testKey + `"`,
		want:  []veles.Secret{mistralapikey.MistralAPIKey{Key: testKey}},
	}, {
		name:  "context_MixedCase_Mistral",
		input: "Mistral " + testKey,
		want:  []veles.Secret{mistralapikey.MistralAPIKey{Key: testKey}},
	}, {
		name:  "context_MISTRAL_uppercase",
		input: "MISTRAL " + testKey,
		want:  []veles.Secret{mistralapikey.MistralAPIKey{Key: testKey}},
	}, {
		name:  "context_MistralAI_camelCase",
		input: "MistralAI " + testKey,
		want:  []veles.Secret{mistralapikey.MistralAPIKey{Key: testKey}},
	}, {
		name:  "context_MistralApiKey_camelCase",
		input: "MistralApiKey=" + testKey,
		want:  []veles.Secret{mistralapikey.MistralAPIKey{Key: testKey}},
	}, {
		name:  "context_mistral-api-key_dash",
		input: "mistral-api-key=" + testKey,
		want:  []veles.Secret{mistralapikey.MistralAPIKey{Key: testKey}},
	}, {
		name:  "context_MistralKey_camelCase",
		input: "MistralKey=" + testKey,
		want:  []veles.Secret{mistralapikey.MistralAPIKey{Key: testKey}},
	}, {
		name:  "context_mistral-key_dash",
		input: "mistral-key=" + testKey,
		want:  []veles.Secret{mistralapikey.MistralAPIKey{Key: testKey}},
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
// will not find a Mistral API key.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{mistralapikey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
	}{{
		name:  "empty_input",
		input: "",
	}, {
		name:  "no_context_32_char_string",
		input: testKey,
	}, {
		name:  "no_context_with_generic_api_key",
		input: "API_KEY=" + testKey,
	}, {
		name:  "no_context_with_generic_token",
		input: "token=" + testKey,
	}, {
		name:  "key_too_short",
		input: "mistral " + testKey[:31],
	}, {
		name:  "key_too_long",
		input: "mistral " + testKey + "x",
	}, {
		name:  "key_with_special_char",
		input: "mistral " + testKey[:16] + "-" + testKey[17:],
	}, {
		name:  "key_part_of_larger_base64_blob",
		input: "mistral " + "XXXX" + testKey + "YYYY",
	}, {
		name:  "context_too_far_away",
		input: "mistral" + strings.Repeat(" ", 300) + testKey,
	}, {
		name:  "unrelated_context",
		input: "openai " + testKey,
	}, {
		name:  "partial_mistral_word",
		input: "amistralb " + testKey,
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if len(got) != 0 {
				t.Errorf("Detect() = %v, want empty", got)
			}
		})
	}
}
