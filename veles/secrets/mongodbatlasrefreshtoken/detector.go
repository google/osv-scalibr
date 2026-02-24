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

// Package mongodbatlasrefreshtoken contains a Veles Secret type, Detector, and Validator
// for MongoDB Atlas Refresh Tokens. Detects refresh tokens used to obtain new
// access tokens for the MongoDB Atlas API.
package mongodbatlasrefreshtoken

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

const (
	// maxTokenLength is the maximum length of a MongoDB Atlas Refresh Token match.
	// The prefix "refresh_token" plus separators plus the token itself.
	maxTokenLength = 2100
)

var (
	// refreshTokenRe matches a MongoDB Atlas refresh token assignment: the keyword "refresh_token"
	// followed by a separator (= or :), optional whitespace and quotes, then a base64url-encoded
	// token value. The token is captured in group 1.
	refreshTokenRe = regexp.MustCompile(`refresh_token\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})`)
)

var _ veles.Detector = NewDetector()

// NewDetector returns a new Detector that matches MongoDB Atlas Refresh Tokens.
// It uses a simpletoken Detector with a regex that matches "refresh_token" assignments
// containing base64url-encoded refresh token strings.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     refreshTokenRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			matches := refreshTokenRe.FindSubmatch(b)
			if len(matches) < 2 {
				return nil, false
			}
			return MongoDBAtlasRefreshToken{Token: string(matches[1])}, true
		},
	}
}
