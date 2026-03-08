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
)

func TestFeatureFlagsClientTokenDetector_FindSecrets(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name: "valid_feature_flags_token_with_endpoint",
			input: `
				url = https://gitlab.com/api/v4/feature_flags/unleash/79858780
				token = glffct-KH5TUFTqs5ysYsDxPz24
			`,
			want: []veles.Secret{
				gitlab.FeatureFlagsClientToken{
					Token:    "glffct-KH5TUFTqs5ysYsDxPz24",
					Endpoint: "https://gitlab.com/api/v4/feature_flags/unleash/79858780",
				},
			},
		},
		{
			name: "valid_feature_flags_token_with_different_endpoint",
			input: `
				endpoint: https://gitlab.example.com/api/v4/feature_flags/unleash/12345678
				client_token: glffct-wwGhXf4qa_VYq7oHC7Xy
			`,
			want: []veles.Secret{
				gitlab.FeatureFlagsClientToken{
					Token:    "glffct-wwGhXf4qa_VYq7oHC7Xy",
					Endpoint: "https://gitlab.example.com/api/v4/feature_flags/unleash/12345678",
				},
			},
		},
		{
			name: "multiple_tokens_with_endpoints",
			input: `
				# Production
				https://gitlab.com/api/v4/feature_flags/unleash/79858780
				glffct-KH5TUFTqs5ysYsDxPz24
				
				# Staging
				https://gitlab.example.com/api/v4/feature_flags/unleash/99999999
				glffct-bmqmsS3RJHVjkN98sqCy
			`,
			want: []veles.Secret{
				gitlab.FeatureFlagsClientToken{
					Token:    "glffct-KH5TUFTqs5ysYsDxPz24",
					Endpoint: "https://gitlab.com/api/v4/feature_flags/unleash/79858780",
				},
				gitlab.FeatureFlagsClientToken{
					Token:    "glffct-bmqmsS3RJHVjkN98sqCy",
					Endpoint: "https://gitlab.example.com/api/v4/feature_flags/unleash/99999999",
				},
			},
		},
		{
			name: "token_with_hyphen",
			input: `
				token: glffct-z4xqKDj_ndxrvmnGD6By
				endpoint: https://gitlab.com/api/v4/feature_flags/unleash/11111111
			`,
			want: []veles.Secret{
				gitlab.FeatureFlagsClientToken{
					Token:    "glffct-z4xqKDj_ndxrvmnGD6By",
					Endpoint: "https://gitlab.com/api/v4/feature_flags/unleash/11111111",
				},
			},
		},
		{
			name: "token_only_without_endpoint",
			input: `
				client_token = glffct-KH5TUFTqs5ysYsDxPz24
			`,
			want: []veles.Secret{
				gitlab.FeatureFlagsClientToken{
					Token: "glffct-KH5TUFTqs5ysYsDxPz24",
				},
			},
		},
		{
			name: "token_in_go_code",
			input: `
				unleash.WithUrl("https://gitlab.com/api/v4/feature_flags/unleash/79858780"),
				unleash.WithCustomHeaders(http.Header{"Authorization": {"glffct-KH5TUFTqs5ysYsDxPz24"}}),
			`,
			want: []veles.Secret{
				gitlab.FeatureFlagsClientToken{
					Token:    "glffct-KH5TUFTqs5ysYsDxPz24",
					Endpoint: "https://gitlab.com/api/v4/feature_flags/unleash/79858780",
				},
			},
		},
		{
			name: "self-hosted_gitlab_instance",
			input: `
				https://gitlab.internal.company.com/api/v4/feature_flags/unleash/55555555
				glffct-AbCdEfGhIjKlMnOpQrStUvWxYz123
			`,
			want: []veles.Secret{
				gitlab.FeatureFlagsClientToken{
					Token:    "glffct-AbCdEfGhIjKlMnOpQrStUvWxYz123",
					Endpoint: "https://gitlab.internal.company.com/api/v4/feature_flags/unleash/55555555",
				},
			},
		},
		{
			name: "invalid_token_too_short",
			input: `
				token = glffct-short
				endpoint = https://gitlab.com/api/v4/feature_flags/unleash/79858780
			`,
			want: []veles.Secret{},
		},
		{
			name: "invalid_prefix",
			input: `
				token = glpat-KH5TUFTqs5ysYsDxPz24
				endpoint = https://gitlab.com/api/v4/feature_flags/unleash/79858780
			`,
			want: []veles.Secret{},
		},
		{
			name: "endpoint_only_no_token",
			input: `
				endpoint = https://gitlab.com/api/v4/feature_flags/unleash/79858780
			`,
			want: []veles.Secret{},
		},
	}

	detector := gitlab.NewFeatureFlagsClientTokenDetector()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := detector.Detect([]byte(tt.input))
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Detect() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
