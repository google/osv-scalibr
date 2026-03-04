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

package gitlabincomingemailtoken_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gitlabincomingemailtoken"
)

func TestDetector_FindSecrets(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name: "valid_token_26_chars",
			input: `
				GITLAB_INCOMING_EMAIL_TOKEN=glimt-3xd28hqc2nnlc6nslnt2elhymg
			`,
			want: []veles.Secret{
				gitlabincomingemailtoken.GitlabIncomingEmailToken{
					Token: "glimt-3xd28hqc2nnlc6nslnt2elhymg",
				},
			},
		},
		{
			name: "valid_token_25_chars",
			input: `
				token: glimt-1yxdtvd3hr14wiegu1zo2hudq
			`,
			want: []veles.Secret{
				gitlabincomingemailtoken.GitlabIncomingEmailToken{
					Token: "glimt-1yxdtvd3hr14wiegu1zo2hudq",
				},
			},
		},
		{
			name: "valid_token_in_config",
			input: `
				incoming_email:
				  token: glimt-f4bc97n60khq4ejxid7swcwqq
			`,
			want: []veles.Secret{
				gitlabincomingemailtoken.GitlabIncomingEmailToken{
					Token: "glimt-f4bc97n60khq4ejxid7swcwqq",
				},
			},
		},
		{
			name: "multiple_tokens",
			input: `
				token1: glimt-3xd28hqc2nnlc6nslnt2elhymg
				token2: glimt-1yxdtvd3hr14wiegu1zo2hudq
			`,
			want: []veles.Secret{
				gitlabincomingemailtoken.GitlabIncomingEmailToken{
					Token: "glimt-3xd28hqc2nnlc6nslnt2elhymg",
				},
				gitlabincomingemailtoken.GitlabIncomingEmailToken{
					Token: "glimt-1yxdtvd3hr14wiegu1zo2hudq",
				},
			},
		},
		{
			name: "token_in_json",
			input: `
				{"incoming_email_token": "glimt-f4bc97n60khq4ejxid7swcwqq"}
			`,
			want: []veles.Secret{
				gitlabincomingemailtoken.GitlabIncomingEmailToken{
					Token: "glimt-f4bc97n60khq4ejxid7swcwqq",
				},
			},
		},
		{
			name: "invalid_token_too_short",
			input: `
				glimt-short123
			`,
			want: nil,
		},
		{
			name: "token_with_extra_chars_matches_first_26",
			input: `
				glimt-1234567890123456789012345678901234567890
			`,
			want: []veles.Secret{
				gitlabincomingemailtoken.GitlabIncomingEmailToken{
					Token: "glimt-12345678901234567890123456",
				},
			},
		},
		{
			name: "invalid_token_uppercase",
			input: `
				glimt-3XD28HQC2NNLC6NSLNT2ELHYMG
			`,
			want: nil,
		},
		{
			name: "invalid_token_with_special_chars",
			input: `
				glimt-3xd28hqc2nnlc6nslnt2el_ymg
			`,
			want: nil,
		},
		{
			name: "invalid_wrong_prefix",
			input: `
				glidt-3xd28hqc2nnlc6nslnt2elhymg
			`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := gitlabincomingemailtoken.NewDetector()
			got, _ := detector.Detect([]byte(tt.input))
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Detect() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
