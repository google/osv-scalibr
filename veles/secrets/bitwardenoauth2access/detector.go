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

package bitwardenoauth2access

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	// maxSecretLength is the maximum length of a Bitwarden API key client secret.
	maxSecretLength = 50

	// maxDistance is the maximum distance between the keyword and the secret value.
	// Accounts for separators like `:`, whitespace, and quotes in JSON formatting.
	maxDistance = 20
)

var (
	// keywordRe matches the Bitwarden CLI data.json key pattern for API key client secrets.
	// Pattern: "user_<UUID>_token_apiKeyClientSecret" followed by a JSON separator.
	// The UUID is captured in a submatch group for extraction as the client ID.
	keywordRe = regexp.MustCompile(
		`"user_([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})_token_apiKeyClientSecret"\s*:`,
	)

	// secretRe matches the client secret value: an alphanumeric string (10-50 chars)
	// typically found as a quoted JSON value.
	secretRe = regexp.MustCompile(`"([A-Za-z0-9]{10,50})"`)
)

var _ veles.Detector = NewDetector()

// NewDetector returns a new Detector that matches
// Bitwarden OAuth2 access tokens by finding a keyword-secret pair
// in Bitwarden CLI data.json files.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: maxSecretLength,
		MaxDistance:   maxDistance,
		FindA:         pair.FindAllMatches(keywordRe),
		FindB:         pair.FindAllMatches(secretRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			// Extract the client ID (UUID) from the keyword submatch.
			keyMatch := keywordRe.FindSubmatch(p.A.Value)
			if len(keyMatch) < 2 {
				return nil, false
			}
			clientID := string(keyMatch[1])

			// Extract the client secret from the value submatch.
			secretMatch := secretRe.FindSubmatch(p.B.Value)
			if len(secretMatch) < 2 {
				return nil, false
			}
			clientSecret := string(secretMatch[1])

			return Token{
				ClientID:     clientID,
				ClientSecret: clientSecret,
			}, true
		},
	}
}
