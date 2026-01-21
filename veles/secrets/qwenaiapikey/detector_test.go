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

package qwenaiapikey_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/qwenaiapikey"
)

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{qwenaiapikey.NewDetector()})
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
			input: "qwen_api_key: sk-2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7", // 31 hex chars
			want:  nil,
		},
		{
			name:  "invalid_token_format_wrong_prefix",
			input: "qwen_api_key: pk-2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c",
			want:  nil,
		},
		{
			name:  "invalid_token_format_uppercase",
			input: "qwen_api_key: sk-2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C", // regex expects lowercase
			want:  nil,
		},
		{
			name:  "keyword_but_no_secret",
			input: `qwen://SOMEOTHERFORMAT123`,
			want:  nil,
		},
		{
			name:  "false_positive_token_but_no_keyword",
			input: `config: sk-2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c`,
			want:  nil,
		},
		{
			name:  "valid_key_with_qwen_keyword",
			input: `qwen_api_key: sk-2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c`,
			want: []veles.Secret{
				qwenaiapikey.QwenAIAPIKey{
					Key: "sk-2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c",
				},
			},
		},
		{
			name:  "valid_key_with_dashscope_keyword",
			input: `DASHSCOPE_API_KEY=sk-2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c`,
			want: []veles.Secret{
				qwenaiapikey.QwenAIAPIKey{
					Key: "sk-2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c",
				},
			},
		},
		{
			name:  "valid_key_with_aliyun_keyword",
			input: `aliyun_api_key: sk-2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c`,
			want: []veles.Secret{
				qwenaiapikey.QwenAIAPIKey{
					Key: "sk-2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c",
				},
			},
		},
		{
			name: "far_apart_token",
			input: `qwen:
AAAAAAAAAA` + strings.Repeat("\nfiller line with random data", 100) + `
sk-2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c`,
			want: nil,
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
