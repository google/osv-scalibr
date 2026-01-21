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

package discordbottoken_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/discordbottoken"
)

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{discordbottoken.NewDetector()})
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
			name:  "invalid_token_format_wrong_prefix",
			input: "discord bot_token: AABC123456789012345678.G1ab2c.abcdefghijklmnopqrstuvwxyzabc",
			want:  nil,
		},
		{
			name:  "invalid_token_format_too_short_third_part",
			input: "discord bot_token: MTIzNDU2Nzg5MDEyMzQ1Njc4.G1ab2c.short",
			want:  nil,
		},
		{
			name:  "discord_keyword_but_no_secret",
			input: `discord://SOMEOTHERFORMAT123`,
			want:  nil,
		},
		{
			name:  "false_positive_token_but_no_keyword",
			input: `config: MTIzNDU2Nzg5MDEyMzQ1Njc4.G1ab2c.abcdefghijklmnopqrstuvwxyzabc`,
			want:  nil,
		},
		{
			name:  "valid_bot_token_with_discord_keyword",
			input: `discord bot_token: MTIzNDU2Nzg5MDEyMzQ1Njc4.G1ab2c.abcdefghijklmnopqrstuvwxyzabc`,
			want: []veles.Secret{
				discordbottoken.DiscordBotToken{
					Token: "MTIzNDU2Nzg5MDEyMzQ1Njc4.G1ab2c.abcdefghijklmnopqrstuvwxyzabc",
				},
			},
		},
		{
			name:  "valid_bot_token_with_DISCORD_TOKEN_keyword",
			input: `DISCORD_TOKEN=NTEyMzQ1Njc4OTAxMjM0NTY3.Hx9Y8z.ABCDEFghijKLMNOPqrstuvWXYZabcd`,
			want: []veles.Secret{
				discordbottoken.DiscordBotToken{
					Token: "NTEyMzQ1Njc4OTAxMjM0NTY3.Hx9Y8z.ABCDEFghijKLMNOPqrstuvWXYZabcd",
				},
			},
		},
		{
			name:  "valid_bot_token_with_bot_token_keyword",
			input: `bot_token = "MTIzNDU2Nzg5MDEyMzQ1Njc4OQ.abcdef.abcdefghijklmnopqrstuvwxyzabc"`,
			want: []veles.Secret{
				discordbottoken.DiscordBotToken{
					Token: "MTIzNDU2Nzg5MDEyMzQ1Njc4OQ.abcdef.abcdefghijklmnopqrstuvwxyzabc",
				},
			},
		},
		{
			name: "far_apart_token",
			input: `discord:
AAAAAAAAAA` + strings.Repeat("\nfiller line with random data", 500) + `
MTIzNDU2Nzg5MDEyMzQ1Njc4.G1ab2c.abcdefghijklmnopqrstuvwxyzabc`,
			want: nil,
		},
		{
			name:  "token_with_underscores_and_hyphens",
			input: `discord: MTIzNDU2Nzg5MDEyMzQ1Njc4.G_ab-c.abc_def-ghijklmnopqrstu_wxyz-ab`,
			want: []veles.Secret{
				discordbottoken.DiscordBotToken{
					Token: "MTIzNDU2Nzg5MDEyMzQ1Njc4.G_ab-c.abc_def-ghijklmnopqrstu_wxyz-ab",
				},
			},
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
