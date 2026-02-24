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

// Package mongodbatlasaccesstoken contains a Veles Secret type, Detector, and Validator
// for MongoDB Atlas Access Tokens. Detects Okta-issued JWT tokens used to
// authenticate with the MongoDB Atlas API.
package mongodbatlasaccesstoken

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

const (
	// maxTokenLength is the maximum length of a MongoDB Atlas Access Token match.
	// The prefix "access_token" plus separators plus the JWT itself (up to ~2048 chars).
	maxTokenLength = 2100
)

var (
	// accessTokenRe matches a MongoDB Atlas access token assignment: the keyword "access_token"
	// followed by a separator (= or :), optional whitespace and quotes, then a JWT token.
	// The JWT is captured in group 1: three base64url-encoded segments separated by dots
	// (header.payload.signature), where header and payload both start with "eyJ".
	accessTokenRe = regexp.MustCompile(`access_token\s*[=:]\s*['"]?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)`)
)

var _ veles.Detector = NewDetector()

// NewDetector returns a new Detector that matches MongoDB Atlas Access Tokens.
// It uses a simpletoken Detector with a regex that matches "access_token" assignments
// containing Okta-issued JWT tokens (three base64url-encoded segments separated by dots).
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     accessTokenRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			matches := accessTokenRe.FindSubmatch(b)
			if len(matches) < 2 {
				return nil, false
			}
			return MongoDBAtlasAccessToken{Token: string(matches[1])}, true
		},
	}
}
