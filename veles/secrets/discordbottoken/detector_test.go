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

Discord bot token (fake but structurally valid: 24.6.27 characters)
const testToken = "MTIzNDU2Nzg5MDEyMzQ1Njc4.YAaBbC.dEFGhijklMNOPqrSTUVwxyzAB12"

func TestDetector_TruePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{
		discordbottoken.NewDetector(),
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "env var with discord keyword",
			input: `DISCORD_BOT_TOKEN=` + testToken,
			want: []veles.Secret{
								discordbottoken.DiscordBotToken{Token: testToken},
			},
		},
		{
			name:  "config file with discord context",
			input: `discord:\n  bot_token: "` + testToken + `"`,
			want: []veles.Secret{
				discordbottoken.DiscordBotToken{Token: testToken},
			},
		},
		{
			name:  "inline discord bot token",
			input: `my discord bot token is ` + testToken,
			want: []veles.Secret{
				discordbottoken.DiscordBotToken{Token: testToken},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}

			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Fatalf("Detect() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetector_TrueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{
		discordbottoken.NewDetector(),
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "random base64 string",
			input: "YWJjZGVmZ2hpamtsbW5vcA==",
		},
		{
			name:  "token without discord context",
			input: testToken,
		},
		{
			name:  "partial token",
			input: testToken[:20],
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}

			if len(got) != 0 {
				t.Fatalf("Detect() = %v, want no secrets", got)
			}
		})
	}
}
