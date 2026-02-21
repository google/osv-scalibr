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

package tinkkeyset

import (
	"encoding/base64"
	"regexp"
	"testing"
)

func TestBase64PatternIncluding_Matching(t *testing.T) {
	tests := []struct {
		name      string
		plaintext string
		target    string
		wantMatch bool
	}{
		{
			name:      "exact_standalone_match",
			plaintext: "tink",
			target:    base64.StdEncoding.EncodeToString([]byte("tink")),
			wantMatch: true,
		},
		{
			name:      "match_with_the_exact_space_padding_from_current_implementation",
			plaintext: "tink",
			target:    base64.StdEncoding.EncodeToString([]byte(" tink")),
			wantMatch: true,
		},
		{
			name:      "embedded_inside_larger_string_(shift_0)",
			plaintext: "tink",
			target:    base64.StdEncoding.EncodeToString([]byte("my_tink_keyset")),
			wantMatch: true,
		},
		{
			name:      "embedded_inside_larger_string_(shift_1)",
			plaintext: "tink",
			target:    base64.StdEncoding.EncodeToString([]byte("my_tink_keysets")),
			wantMatch: true,
		},
		{
			name:      "embedded_inside_larger_string_(shift_2)",
			plaintext: "tink",
			target:    base64.StdEncoding.EncodeToString([]byte("my_tink_keysetss")),
			wantMatch: true,
		},
		{
			name:      "does_not_contain_plaintext",
			plaintext: "tink",
			target:    base64.StdEncoding.EncodeToString([]byte("totally different string")),
			wantMatch: false,
		},
		{
			name:      "real",
			plaintext: "type.googleapis.com/google.crypto.tink",
			target:    base64.StdEncoding.EncodeToString([]byte("totally different string")),
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := Base64SubstringPattern(tt.plaintext)
			re, err := regexp.Compile(pattern)
			if err != nil {
				t.Fatalf("Base64PatternIncluding(%q) generated invalid regex: %v", tt.plaintext, err)
			}

			gotMatch := re.MatchString(tt.target)
			if gotMatch != tt.wantMatch {
				t.Errorf("\nTarget Base64: %s (Decoded: %q)\nRegex Pattern: %s\nMatchString() = %v; want %v",
					tt.target,
					func() string {
						b, _ := base64.StdEncoding.DecodeString(tt.target)
						return string(b)
					}(),
					pattern,
					gotMatch,
					tt.wantMatch)
			}
		})
	}
}
