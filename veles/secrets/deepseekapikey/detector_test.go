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

package deepseekapikey_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/deepseekapikey"
)

const (
	testKey    = "sk-15ac903f2e481u3d4f9g2u3ia8e2b73n"
	anotherKey = "sk-abcd1234567890abcdef1234567890ab"
)

func TestDetector(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{deepseekapikey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "valid_key",
		input: testKey,
		want: []veles.Secret{
			deepseekapikey.APIKey{Key: testKey},
		},
	}, {
		name:  "another_valid_key",
		input: anotherKey,
		want: []veles.Secret{
			deepseekapikey.APIKey{Key: anotherKey},
		},
	}, {
		name:  "multiple_keys",
		input: testKey + " " + anotherKey,
		want: []veles.Secret{
			deepseekapikey.APIKey{Key: testKey},
			deepseekapikey.APIKey{Key: anotherKey},
		},
	}, {
		name:  "key_in_text",
		input: "My DeepSeek API key is: " + testKey + " please keep it safe",
		want: []veles.Secret{
			deepseekapikey.APIKey{Key: testKey},
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
	engine, err := veles.NewDetectionEngine([]veles.Detector{deepseekapikey.NewDetector()})
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
		name:  "wrong_prefix",
		input: "sk-openai-15ac903f2e481u3d4f9g2u3ia8e2b73n",
	}, {
		name:  "too_short",
		input: "sk-15ac903f",
	}, {
		name:  "too_long",
		input: "sk-15ac903f2e481u3d4f9g2u3ia8e2b73n1234567890",
	}, {
		name:  "invalid_characters",
		input: "sk-15ac903f2e481u3d4f9g2u3ia8e2b73Z",
	}, {
		name:  "uppercase_hex",
		input: "sk-15AC903F2E481U3D4F9G2U3IA8E2B73N",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if len(got) != 0 {
				t.Errorf("Detect() found %d secrets, want 0", len(got))
			}
		})
	}
}
