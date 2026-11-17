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

package cohereapikey

import (
	"testing"

	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

func TestDetector(t *testing.T) {
	d := NewDetector().(simpletoken.Detector)

	tests := []struct {
		name    string
		input   string
		want    bool
		wantKey string
	}{
		{
			name:    "valid cohere v2 key",
			input:   `COHERE_API_KEY=sk-co-abcdefghijklmnopqrstuvwxyz1234567890abcd`,
			want:    true,
			wantKey: "sk-co-abcdefghijklmnopqrstuvwxyz1234567890abcd",
		},
		{
			name:    "valid cohere key in code",
			input:   `cohere_key = "sk-co-AbCdEfGhIjKlMnOpQrStUvWx0123456789"`,
			want:    true,
			wantKey: "sk-co-AbCdEfGhIjKlMnOpQrStUvWx0123456789",
		},
		{
			name:    "valid key with underscores and hyphens",
			input:   `key: sk-co-abc_def-ghi_jkl-mno_pqr-stu_vwx`,
			want:    true,
			wantKey: "sk-co-abc_def-ghi_jkl-mno_pqr-stu_vwx",
		},
		{
			name:  "no match - wrong prefix",
			input: `API_KEY=sk-ant-abcdefghijklmnopqrstuvwxyz`,
			want:  false,
		},
		{
			name:  "no match - too short",
			input: `key=sk-co-abc`,
			want:  false,
		},
		{
			name:  "no match - no key present",
			input: `This is just regular text without any API keys.`,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := d.Re.FindAll([]byte(tt.input), -1)
			got := len(matches) > 0
			if got != tt.want {
				t.Errorf("Detector match = %v, want %v", got, tt.want)
			}
			if tt.want && got {
				if string(matches[0]) != tt.wantKey {
					t.Errorf("Detector matched %q, want %q", string(matches[0]), tt.wantKey)
				}
			}
		})
	}
}
