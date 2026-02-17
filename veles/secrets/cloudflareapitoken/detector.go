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

// Package cloudflareapitoken contains a Veles Secret type, Detector, and Validator
// for Cloudflare API Tokens. Detects 40-character tokens in environment variables,
// JSON, and YAML formats.
package cloudflareapitoken

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	// maxTokenLength is the maximum length of a Cloudflare API Token (40 chars).
	maxTokenLength = 40

	// maxDistance is the maximum distance between the keyword and the token value.
	// Accounts for separators like `=`, `:`, whitespace, quotes, and JSON formatting.
	maxDistance = 20
)

var (
	// keywordRe matches Cloudflare-related context keywords (case-insensitive),
	// optionally surrounded by quotes, followed by a separator (= or :).
	// Handles env var (KEY=), JSON ("KEY":), and YAML (key:) formats.
	keywordRe = regexp.MustCompile(
		`(?i)["']?\b(?:CLOUDFLARE_API_TOKEN|CLOUDFLARE_API_KEY|CF_API_TOKEN|CF_API_KEY|CLOUDFLARE_TOKEN|CF_TOKEN|CLOUDFLARE_AUTH_KEY|CF_ACCOUNT_ID)\b["']?\s*[=:]`,
	)

	// tokenRe matches a 40-character alphanumeric token (with underscores and hyphens).
	tokenRe = regexp.MustCompile(`\b[A-Za-z0-9_-]{40}\b`)
)

var _ veles.Detector = NewDetector()

// NewDetector returns a new Detector that matches
// Cloudflare API Tokens by finding a keyword-token pair.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxTokenLength,
		MaxDistance:   maxDistance,
		FindA:         pair.FindAllMatches(keywordRe),
		FindB:         pair.FindAllMatches(tokenRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return CloudflareAPIToken{Token: string(p.B.Value)}, true
		},
	}
}
