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

package gitlab_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gitlab"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	testFeedToken1 = "glft-Ua8LJQoqMt3YjhW-UqxV"
	testFeedToken2 = "glft-SkQDaK_81q7wB2G-Ze-Z"
	testFeedToken3 = "glft-dVtnfc2zBubZH1saymzz"
)

func TestFeedTokenDetectorAcceptance(t *testing.T) {
	d := gitlab.NewFeedTokenDetector()
	cases := []struct {
		name   string
		input  string
		secret veles.Secret
	}{
		{
			name:  "token_with_gitlab_com",
			input: testFeedToken1 + "\nhttps://gitlab.com",
			secret: gitlab.FeedToken{
				Token:    testFeedToken1,
				Hostname: "gitlab.com",
			},
		},
		{
			name:  "token_with_custom_hostname",
			input: testFeedToken2 + "\nhttps://gitlab.example.com",
			secret: gitlab.FeedToken{
				Token:    testFeedToken2,
				Hostname: "gitlab.example.com",
			},
		},
		{
			name:  "token_in_url",
			input: "https://gitlab.com/dashboard/projects.atom?feed_token=" + testFeedToken3,
			secret: gitlab.FeedToken{
				Token:    testFeedToken3,
				Hostname: "gitlab.com",
			},
		},
		{
			name:  "token_without_hostname",
			input: testFeedToken1,
			secret: gitlab.FeedToken{
				Token:    testFeedToken1,
				Hostname: "",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			velestest.AcceptDetector(
				t,
				d,
				tc.input,
				tc.secret,
				velestest.WithBackToBack(),
				velestest.WithPad('a'),
			)
		})
	}
}

func TestFeedTokenDetector_FindSecrets(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name: "valid_token_with_gitlab_com",
			input: `
				GITLAB_FEED_TOKEN=glft-Ua8LJQoqMt3YjhW-UqxV
				GITLAB_URL=https://gitlab.com
			`,
			want: []veles.Secret{
				gitlab.FeedToken{
					Token:    "glft-Ua8LJQoqMt3YjhW-UqxV",
					Hostname: "gitlab.com",
				},
			},
		},
		{
			name: "valid_token_with_custom_hostname",
			input: `
				feed_token: glft-SkQDaK_81q7wB2G-Ze-Z
				gitlab_url: https://gitlab.example.com
			`,
			want: []veles.Secret{
				gitlab.FeedToken{
					Token:    "glft-SkQDaK_81q7wB2G-Ze-Z",
					Hostname: "gitlab.example.com",
				},
			},
		},
		{
			name: "valid_token_in_url",
			input: `
				curl -L https://gitlab.com/dashboard/projects.atom?feed_token=glft-dVtnfc2zBubZH1saymzz
			`,
			want: []veles.Secret{
				gitlab.FeedToken{
					Token:    "glft-dVtnfc2zBubZH1saymzz",
					Hostname: "gitlab.com",
				},
			},
		},
		{
			name: "valid_token_with_self_hosted",
			input: `
				https://git.company.org/dashboard/projects.atom?feed_token=glft-Ua8LJQoqMt3YjhW-UqxV
			`,
			want: []veles.Secret{
				gitlab.FeedToken{
					Token:    "glft-Ua8LJQoqMt3YjhW-UqxV",
					Hostname: "git.company.org",
				},
			},
		},
		{
			name: "token_without_hostname_defaults_to_gitlab_com",
			input: `
				FEED_TOKEN=glft-SkQDaK_81q7wB2G-Ze-Z
			`,
			want: []veles.Secret{
				gitlab.FeedToken{
					Token:    "glft-SkQDaK_81q7wB2G-Ze-Z",
					Hostname: "",
				},
			},
		},
		{
			name: "multiple_tokens_with_different_hostnames",
			input: `
				token1: glft-Ua8LJQoqMt3YjhW-UqxV
				url1: https://gitlab.com
				token2: glft-SkQDaK_81q7wB2G-Ze-Z
				url2: https://gitlab.example.com
			`,
			want: []veles.Secret{
				gitlab.FeedToken{
					Token:    "glft-Ua8LJQoqMt3YjhW-UqxV",
					Hostname: "gitlab.com",
				},
				gitlab.FeedToken{
					Token:    "glft-SkQDaK_81q7wB2G-Ze-Z",
					Hostname: "gitlab.example.com",
				},
			},
		},
		{
			name: "token_in_json",
			input: `
				{"feed_token": "glft-dVtnfc2zBubZH1saymzz", "gitlab_url": "https://gitlab.com"}
			`,
			want: []veles.Secret{
				gitlab.FeedToken{
					Token:    "glft-dVtnfc2zBubZH1saymzz",
					Hostname: "gitlab.com",
				},
			},
		},
		{
			name: "invalid_token_too_short",
			input: `
				glft-short123
			`,
			want: nil,
		},
		{
			name: "invalid_token_too_long",
			input: `
				glft-Ua8LJQoqMt3YjhW-UqxVextra
			`,
			want: []veles.Secret{
				gitlab.FeedToken{
					Token:    "glft-Ua8LJQoqMt3YjhW-UqxV",
					Hostname: "",
				},
			},
		},
		{
			name: "invalid_wrong_prefix",
			input: `
				glpt-Ua8LJQoqMt3YjhW-UqxV
			`,
			want: nil,
		},
		{
			name: "token_with_http_url",
			input: `
				http://gitlab.internal.net/dashboard/projects.atom?feed_token=glft-Ua8LJQoqMt3YjhW-UqxV
			`,
			want: []veles.Secret{
				gitlab.FeedToken{
					Token:    "glft-Ua8LJQoqMt3YjhW-UqxV",
					Hostname: "gitlab.internal.net",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := gitlab.NewFeedTokenDetector()
			got, _ := detector.Detect([]byte(tt.input))
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Detect() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
