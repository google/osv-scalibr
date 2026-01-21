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

package squareapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Detector = NewPersonalAccessTokenDetector()
	_ veles.Detector = NewOAuthApplicationSecretDetector()
)

// Regex for Square Personal Access Tokens.
// Format: Always starts with "EAAA" followed by 60 characters.
// Allowed characters: alphanumeric, "-", "+", "="
// Example length = 64 (4 prefix + 60 random chars)
const personalAccessTokenMaxLen = 64

// Compiled regex for matching Square Personal Access Tokens.
var personalAccessTokenRe = regexp.MustCompile(`EAAA[\w\-\+\=]{60}`)

// Regex for Square OAuth Application IDs.
// Format: Always starts with "sq0idp-" followed by 22 characters.
// Allowed characters: alphanumeric, "_", "-"
const oAuthApplicationIDMaxLen = 29 // sq0idp- (7 chars) + 22 chars = 29 total

// Compiled regex for matching Square OAuth Application IDs.
var oAuthApplicationIDRe = regexp.MustCompile(`sq0idp-[A-Za-z0-9_-]{22}`)

// Regex for Square OAuth Application Secrets.
// Format: Always starts with "sq0csp-" followed by 43 characters.
// Allowed characters: alphanumeric, "_", "-"
const oAuthApplicationSecretMaxLen = 50 // sq0csp- (7 chars) + 43 chars = 50 total

// Compiled regex for matching Square OAuth Application Secrets.
var oAuthApplicationSecretRe = regexp.MustCompile(`sq0csp-[A-Za-z0-9_-]{43}`)

const (
	// maxDistance is the maximum distance between OAuth Application ID and Secret to be considered for pairing.
	// 10 KiB is a good upper bound as we don't expect files containing credentials to be larger than this.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

// NewPersonalAccessTokenDetector returns a detector for Square Personal Access Tokens.
func NewPersonalAccessTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: personalAccessTokenMaxLen,
		Re:     personalAccessTokenRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return SquarePersonalAccessToken{Key: string(b)}, true
		},
	}
}

// NewOAuthApplicationSecretDetector returns a detector for Square OAuth Application Secrets.
// It uses pair detection to find both the Application ID (sq0idp-) and Secret (sq0csp-).
func NewOAuthApplicationSecretDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(oAuthApplicationIDMaxLen, oAuthApplicationSecretMaxLen),
		MaxDistance:   uint32(maxDistance),
		FindA:         pair.FindAllMatches(oAuthApplicationIDRe),
		FindB:         pair.FindAllMatches(oAuthApplicationSecretRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return SquareOAuthApplicationSecret{
				ID:  string(p.A.Value),
				Key: string(p.B.Value),
			}, true
		},
		FromPartialPair: func(p pair.Pair) (veles.Secret, bool) {
			// If we only have the secret without the ID, still report it
			if p.B != nil {
				return SquareOAuthApplicationSecret{
					Key: string(p.B.Value),
				}, true
			}
			// If we only have the ID without the secret, don't report it
			return nil, false
		},
	}
}
