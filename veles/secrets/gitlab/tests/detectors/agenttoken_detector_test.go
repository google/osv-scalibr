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

package detectors

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gitlab"
	"github.com/google/osv-scalibr/veles/velestest"
)

func TestAgentTokenDetector_truePositives(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []veles.Secret
	}{
		{
			name:    "agent token only",
			content: "glagent-zxsRWawpFVxTVbSo2eoW3m86MQpwOjFiam5cZww.01.130x3u2mr",
			want: []veles.Secret{
				gitlab.AgentToken{Token: "glagent-zxsRWawpFVxTVbSo2eoW3m86MQpwOjFiam5cZww.01.130x3u2mr"},
			},
		},
		{
			name:    "agent token with KAS URL",
			content: "token: glagent-zxsRWawpFVxTVbSo2eoW3m86MQpwOjFiam5cZww.01.130x3u2mr\nkas_url: wss://kas.gitlab.com",
			want: []veles.Secret{
				gitlab.AgentToken{
					Token:  "glagent-zxsRWawpFVxTVbSo2eoW3m86MQpwOjFiam5cZww.01.130x3u2mr",
					KasURL: "wss://kas.gitlab.com",
				},
			},
		},
		{
			name:    "agent token with custom KAS URL",
			content: "glagent-zxsRWawpFVxTVbSo2eoW3m86MQpwOjFiam5cZww.01.130x3u2mr\nwss://kas.gitlab.example.com:8080",
			want: []veles.Secret{
				gitlab.AgentToken{
					Token:  "glagent-zxsRWawpFVxTVbSo2eoW3m86MQpwOjFiam5cZww.01.130x3u2mr",
					KasURL: "wss://kas.gitlab.example.com:8080",
				},
			},
		},
		{
			name:    "multiple agent tokens",
			content: "token1: glagent-zxsRWawpFVxTVbSo2eoW3m86MQpwOjFiam5cZww.01.130x3u2mr\ntoken2: glagent-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJ.02.140y4v3ns",
			want: []veles.Secret{
				gitlab.AgentToken{Token: "glagent-zxsRWawpFVxTVbSo2eoW3m86MQpwOjFiam5cZww.01.130x3u2mr"},
				gitlab.AgentToken{Token: "glagent-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJ.02.140y4v3ns"},
			},
		},
		{
			name:    "agent token with underscores and dashes",
			content: "glagent-abc_def-123_456-789_012-345_678-901_234-567_890.03.150z5w4ot",
			want: []veles.Secret{
				gitlab.AgentToken{Token: "glagent-abc_def-123_456-789_012-345_678-901_234-567_890.03.150z5w4ot"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := gitlab.NewAgentTokenDetector()
			secrets, _ := detector.Detect([]byte(tt.content))

			if diff := cmp.Diff(tt.want, secrets); diff != "" {
				t.Errorf("AgentTokenDetector.Detect() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAgentTokenDetector_trueNegatives(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "too short token",
			content: "glagent-short",
		},
		{
			name:    "wrong prefix",
			content: "glpat-zxsRWawpFVxTVbSo2eoW3m86MQpwOjFiam5cZww.01.130x3u2mr",
		},
		{
			name:    "invalid characters",
			content: "glagent-zxsRWawpFVxTVbSo2eoW3m86MQpwOjFiam5cZww@01#130x3u2mr",
		},
		{
			name:    "no token",
			content: "just some random text without any tokens",
		},
		{
			name:    "non-KAS URL",
			content: "wss://gitlab.com",
		},
		{
			name:    "https URL instead of wss",
			content: "https://kas.gitlab.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := gitlab.NewAgentTokenDetector()
			secrets, _ := detector.Detect([]byte(tt.content))

			if len(secrets) > 0 {
				t.Errorf("AgentTokenDetector.Detect() expected no secrets, got %d", len(secrets))
			}
		})
	}
}

func TestAgentTokenDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		gitlab.NewAgentTokenDetector(),
		`glagent-zxsRWawpFVxTVbSo2eoW3m86MQpwOjFiam5cZww.01.130x3u2mr
wss://kas.gitlab.com`,
		gitlab.AgentToken{
			Token:  "glagent-zxsRWawpFVxTVbSo2eoW3m86MQpwOjFiam5cZww.01.130x3u2mr",
			KasURL: "wss://kas.gitlab.com",
		},
	)
}
