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

package gcpoauth2token

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of a GCP OAuth2 access token.
const maxTokenLength = 200

// tokenRe is a regular expression that matches GCP OAuth2 access tokens.
// Pattern: ya29. followed by alphanumeric characters, underscores, and hyphens (case-insensitive)
// Modern GCP OAuth2 access tokens start with "ya29." prefix
// https://cloud.google.com/docs/authentication/token-types#access-tokens
var tokenRe = regexp.MustCompile(`\b(ya29\.(?i:[a-z0-9_-]{10,}))(?:[^a-z0-9_-]|\z)`)

// NewDetector returns a new simpletoken.Detector that matches GCP OAuth2 access tokens.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     tokenRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			// Extract the first capturing group which contains the actual token
			matches := tokenRe.FindSubmatch(b)
			if len(matches) >= 2 {
				return GCPOAuth2AccessToken{Token: string(matches[1])}, true
			}
			// Fallback to full match if no capturing group found
			return GCPOAuth2AccessToken{Token: string(b)}, true
		},
	}
}
