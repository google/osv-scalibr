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

// Package cloudflareapitoken contains a Veles Secret type, Detector, and Validator
// for Cloudflare API Tokens. Detects 40-character tokens in environment variables,
// JSON, and YAML formats.
package cloudflareapitoken

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
)

// maxTokenLength is the maximum size of a Cloudflare API Token.
const maxTokenLength = 40

// envVarRe matches environment variable style assignments.
// Examples: CLOUDFLARE_API_TOKEN=token, CF_API_KEY="token"
var envVarRe = regexp.MustCompile(
	`(?i)(CLOUDFLARE_API_TOKEN|CLOUDFLARE_API_KEY|CF_API_TOKEN|CF_API_KEY|CLOUDFLARE_TOKEN|CF_TOKEN|CLOUDFLARE_AUTH_KEY|CF_ACCOUNT_ID)\s*=\s*['"]?([A-Za-z0-9_-]{40})\b['"]?`,
)

// jsonRe matches JSON key-value pairs.
// Examples: "CLOUDFLARE_API_TOKEN": "token", "cloudflare_api_token": "token"
var jsonRe = regexp.MustCompile(
	`(?i)"(cloudflare_api_token|cloudflare_api_key|cf_api_token|cf_api_key|cloudflare_token|cf_token|cloudflare_auth_key|cf_account_id)"\s*:\s*"([A-Za-z0-9_-]{40})\b"`,
)

// yamlRe matches YAML key-value pairs.
// Examples: cloudflare_api_token: token, api_token: "token"
var yamlRe = regexp.MustCompile(
	`(?i)(cloudflare_api_token|cloudflare_api_key|cf_api_token|cf_api_key|cloudflare_token|cf_token|cloudflare_auth_key|cf_account_id|api_token)\s*:\s*['"]?([A-Za-z0-9_-]{40})\b['"]?`,
)

var _ veles.Detector = NewDetector()

// detector is a Veles Detector.
type detector struct{}

// NewDetector returns a new Detector that matches
// Cloudflare API Tokens.
func NewDetector() veles.Detector {
	return &detector{}
}

func (d *detector) MaxSecretLen() uint32 {
	return maxTokenLength
}

func (d *detector) Detect(content []byte) ([]veles.Secret, []int) {
	var secrets []veles.Secret
	var offsets []int
	seenTokens := make(map[string]bool)

	// Define all regex patterns to check
	patterns := []*regexp.Regexp{
		envVarRe,
		jsonRe,
		yamlRe,
	}

	// Check each pattern
	for _, pattern := range patterns {
		matches := pattern.FindAllSubmatchIndex(content, -1)
		for _, match := range matches {
			// match[4] and match[5] contain the start and end indices of the second capture group (the token)
			if len(match) >= 6 {
				tokenStart := match[4]
				tokenEnd := match[5]
				token := string(content[tokenStart:tokenEnd])

				if !seenTokens[token] {
					secrets = append(secrets, CloudflareAPIToken{
						Token: token,
					})
					offsets = append(offsets, tokenStart)
					seenTokens[token] = true
				}
			}
		}
	}

	return secrets, offsets
}
