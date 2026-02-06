package discordbottoken_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/discordbottoken"
)

// Example Discord bot token (fake but structurally valid)
const testToken = "MTIzNDU2Nzg5MDEyMzQ1Njc4.YAaBbC.dEFGhijklMNOPqrSTUVwxyzAB"

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
				&discordbottoken.DiscordBotToken{},
			},
		},
		{
			name:  "config file with discord context",
			input: `discord:\n  bot_token: "` + testToken + `"`,
			want: []veles.Secret{
				&discordbottoken.DiscordBotToken{},
			},
		},
		{
			name:  "inline discord bot token",
			input: `my discord bot token is ` + testToken,
			want: []veles.Secret{
				&discordbottoken.DiscordBotToken{},
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
