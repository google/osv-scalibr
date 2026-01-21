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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/mistralapikey"
)

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{mistralapikey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "empty_input",
			input: "",
			want:  nil,
		},
		{
			name:  "invalid_token_format_too_short",
			input: "mistral_api_key: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p", // 31 chars
			want:  nil,
		},
		{
			name:  "valid_key_with_mistral_keyword",
			input: `mistral_api_key: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6`,
			want: []veles.Secret{
				mistralapikey.MistralAPIKey{
					Key: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
				},
			},
		},
		{
			name:  "valid_key_with_uppercase",
			input: `MISTRAL_API_KEY=A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6`,
			want: []veles.Secret{
				mistralapikey.MistralAPIKey{
					Key: "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6",
				},
			},
		},
		{
			name:  "false_positive_token_but_no_keyword",
			input: `config: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6`,
			want:  nil,
		},
	}

	for _, tc := range tests {
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
