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

const testToken = "glrt-AbCdEfGhIjKlMnOpQrSt"

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		gitlab.NewRunnerAuthTokenDetector(),
		`https://gitlab.com
token = `+testToken,
		gitlab.RunnerAuthToken{Token: testToken, Hostname: "gitlab.com"},
	)
}

func TestRunnerAuthTokenDetector_FindSecrets(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name: "valid_runner_token_with_hostname",
			input: `
				https://gitlab.com
				token = glrt-AbCdEfGhIjKlMnOpQrSt
			`,
			want: []veles.Secret{
				gitlab.RunnerAuthToken{
					Token:    "glrt-AbCdEfGhIjKlMnOpQrSt",
					Hostname: "gitlab.com",
				},
			},
		},
		{
			name: "valid_runner_token_with_versioned_format",
			input: `
				https://gitlab.example.com
				glrt-1j1a9gv3d_AbCdEfGhIjKlMnOp.01.AbCdEfGhIj
			`,
			want: []veles.Secret{
				gitlab.RunnerAuthToken{
					Token:    "glrt-1j1a9gv3d_AbCdEfGhIjKlMnOp.01.AbCdEfGhIj",
					Hostname: "gitlab.example.com",
				},
			},
		},
		{
			name: "valid_runner_token_with_long_versioned_format",
			input: `
				https://gitlab.com
				glrt-0pomZyd4VSw4oyDDd20dU286aQpwOjFiam5mZwp0OjMKsTo5NTBwZRg.01.1j1a9gv3d
			`,
			want: []veles.Secret{
				gitlab.RunnerAuthToken{
					Token:    "glrt-0pomZyd4VSw4oyDDd20dU286aQpwOjFiam5mZwp0OjMKsTo5NTBwZRg.01.1j1a9gv3d",
					Hostname: "gitlab.com",
				},
			},
		},
		{
			name: "valid_runner_token_without_hostname",
			input: `
				token: glrt-W6xaS96Cxzb87K5XsdAh
			`,
			want: []veles.Secret{
				gitlab.RunnerAuthToken{
					Token: "glrt-W6xaS96Cxzb87K5XsdAh",
				},
			},
		},
		{
			name: "runner_token_with_underscores_and_dashes",
			input: `
				https://gitlab.company.com
				glrt-k3tx_ycYvssk_8FLU-Hju
			`,
			want: []veles.Secret{
				gitlab.RunnerAuthToken{
					Token:    "glrt-k3tx_ycYvssk_8FLU-Hju",
					Hostname: "gitlab.company.com",
				},
			},
		},
		{
			name: "self_hosted_gitlab_instance",
			input: `
				https://git.internal.company.com
				runner_token = glrt-AbCdEfGhIjKlMnOpQrStUvWxYz123
			`,
			want: []veles.Secret{
				gitlab.RunnerAuthToken{
					Token:    "glrt-AbCdEfGhIjKlMnOpQrStUvWxYz123",
					Hostname: "git.internal.company.com",
				},
			},
		},
		{
			name: "multiple_tokens_different_hostnames",
			input: `
				https://gitlab.com
				glrt-FirstTokenHere12345678901234567890
				
				https://gitlab.example.com
				glrt-SecondTokenHere67890123456789012345
			`,
			want: []veles.Secret{
				gitlab.RunnerAuthToken{
					Token:    "glrt-FirstTokenHere12345678901234567890",
					Hostname: "gitlab.com",
				},
				gitlab.RunnerAuthToken{
					Token:    "glrt-SecondTokenHere67890123456789012345",
					Hostname: "gitlab.example.com",
				},
			},
		},
		{
			name: "token_in_environment_variable",
			input: `
				GITLAB_RUNNER_TOKEN=glrt-EnvVarToken123456789
			`,
			want: []veles.Secret{
				gitlab.RunnerAuthToken{
					Token: "glrt-EnvVarToken123456789",
				},
			},
		},
		{
			name: "token_in_config_file",
			input: `
				[[runners]]
				  url = "https://gitlab.example.org"
				  token = "glrt-ConfigFileToken12345"
				  executor = "docker"
			`,
			want: []veles.Secret{
				gitlab.RunnerAuthToken{
					Token:    "glrt-ConfigFileToken12345",
					Hostname: "gitlab.example.org",
				},
			},
		},
		{
			name: "token_with_http_protocol",
			input: `
				http://localhost:8080
				glrt-LocalhostToken123456789012345
			`,
			want: []veles.Secret{
				gitlab.RunnerAuthToken{
					Token:    "glrt-LocalhostToken123456789012345",
					Hostname: "localhost:8080",
				},
			},
		},
		{
			name: "no_token_found",
			input: `
				https://gitlab.com
				some random text without a token
			`,
			want: nil,
		},
		{
			name: "invalid_token_too_short",
			input: `
				https://gitlab.com
				glrt-Short123
			`,
			want: nil,
		},
		{
			name: "invalid_token_wrong_prefix",
			input: `
				https://gitlab.com
				glpat-AbCdEfGhIjKlMnOpQrSt
			`,
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			detector := gitlab.NewRunnerAuthTokenDetector()
			got, _ := detector.Detect([]byte(tc.input))
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Detect() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
