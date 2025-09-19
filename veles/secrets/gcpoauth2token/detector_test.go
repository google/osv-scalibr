// Copyright 2025 Google LLC
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

package gcpoauth2token_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gcpoauth2token"
)

func TestDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []veles.Secret
	}{
		{
			name:     "no tokens",
			input:    "This is just plain text with no tokens",
			expected: nil,
		},
		{
			name:  "classic OAuth2 access token",
			input: `access_token: "1/fFAGRNJru1FTz70BzhT3Zg"`,
			expected: []veles.Secret{
				gcpoauth2token.GCPOAuth2AccessToken{Token: "1/fFAGRNJru1FTz70BzhT3Zg"},
			},
		},
		{
			name:  "OAuth2 token in JSON response",
			input: `{"access_token": "1/fFAGRNJru1FTz70BzhT3Zg", "expires_in": 3920, "token_type": "Bearer"}`,
			expected: []veles.Secret{
				gcpoauth2token.GCPOAuth2AccessToken{Token: "1/fFAGRNJru1FTz70BzhT3Zg"},
			},
		},
		{
			name:  "bearer token in Authorization header",
			input: `Authorization: Bearer 1/AbCdEfGhIjKlMnOpQrStUvWxYz1234567890`,
			expected: []veles.Secret{
				gcpoauth2token.GCPOAuth2AccessToken{Token: "1/AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"},
			},
		},
		{
			name:  "longer access token with underscores and hyphens",
			input: `curl -H "Authorization: Bearer 1/aB-cD_eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ"`,
			expected: []veles.Secret{
				gcpoauth2token.GCPOAuth2AccessToken{Token: "1/aB-cD_eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ"},
			},
		},
		{
			name:  "multiple tokens in the same input",
			input: `access_token: "1/FirstToken123" refresh_token: "1/SecondToken456"`,
			expected: []veles.Secret{
				gcpoauth2token.GCPOAuth2AccessToken{Token: "1/FirstToken123"},
				gcpoauth2token.GCPOAuth2AccessToken{Token: "1/SecondToken456"},
			},
		},
		{
			name:  "token in environment variable format",
			input: `export GCP_ACCESS_TOKEN="1/EnvToken987654321"`,
			expected: []veles.Secret{
				gcpoauth2token.GCPOAuth2AccessToken{Token: "1/EnvToken987654321"},
			},
		},
		{
			name: "token in configuration file",
			input: `[auth]
access_token = 1/ConfigToken123456789
token_type = Bearer`,
			expected: []veles.Secret{
				gcpoauth2token.GCPOAuth2AccessToken{Token: "1/ConfigToken123456789"},
			},
		},
		{
			name:     "false positive: token too short",
			input:    `1/abc`,
			expected: nil,
		},
		{
			name:     "false positive: wrong prefix",
			input:    `2/fFAGRNJru1FTz70BzhT3Zg`,
			expected: nil,
		},
		{
			name:     "false positive: no slash",
			input:    `1fFAGRNJru1FTz70BzhT3Zg`,
			expected: nil,
		},
		{
			name:     "false positive: contains invalid characters early",
			input:    `1/fF@AGRNJru1FTz70BzhT3Zg`,
			expected: nil,
		},
		{
			name:     "false positive: contains spaces early",
			input:    `1/fF AGRNJru1FTz70BzhT3Zg`,
			expected: nil,
		},
		{
			name:     "base64 encoded data should not match",
			input:    `data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==`,
			expected: nil,
		},
		{
			name:     "random URL should not match",
			input:    `https://api.example.com/v1/users/123456789/profile`,
			expected: nil,
		},
		{
			name:     "other token formats should not match",
			input:    `sk-1234567890abcdef1234567890abcdef12345678`,
			expected: nil,
		},
		{
			name:  "edge case: exactly minimum length",
			input: `1/abcdefghij`,
			expected: []veles.Secret{
				gcpoauth2token.GCPOAuth2AccessToken{Token: "1/abcdefghij"},
			},
		},
		{
			name:  "edge case: very long token",
			input: `1/` + strings.Repeat("a", 150),
			expected: []veles.Secret{
				gcpoauth2token.GCPOAuth2AccessToken{Token: "1/" + strings.Repeat("a", 150)},
			},
		},
	}

	detector := gcpoauth2token.NewDetector()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets, _ := detector.Detect([]byte(tt.input))

			if diff := cmp.Diff(tt.expected, secrets); diff != "" {
				t.Errorf("Detect() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetector_MaxSecretLen(t *testing.T) {
	detector := gcpoauth2token.NewDetector()
	maxLen := detector.MaxSecretLen()
	if maxLen != 200 {
		t.Errorf("MaxSecretLen() = %d, want 200", maxLen)
	}
}
