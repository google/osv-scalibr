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

// Regex for Square OAuth Application Secrets.
// Format: Always starts with "sq0csp-" followed by 43 characters.
// Allowed characters: alphanumeric, "_", "-"
const oAuthApplicationSecretMaxLen = 50 // sq0csp- (7 chars) + 43 chars = 50 total

// Compiled regex for matching Square OAuth Application Secrets.
var oAuthApplicationSecretRe = regexp.MustCompile(`sq0csp-[A-Za-z0-9_-]{43}`)

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
func NewOAuthApplicationSecretDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: oAuthApplicationSecretMaxLen,
		Re:     oAuthApplicationSecretRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return SquareOAuthApplicationSecret{Key: string(b)}, true
		},
	}
}
