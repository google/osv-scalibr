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

package gcpoauth2access

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// Enforce detector interface.
var _ veles.Detector = NewDetector()

const (
	// maxTokenLength is the maximum size of a GCP OAuth2 access token.
	maxTokenLength = 500
)

var (
	// tokenRe is a regular expression that matches GCP OAuth2 access tokens.
	// Pattern: ya29. followed by alphanumeric characters, underscores, and hyphens (case-insensitive)
	// https://cloud.google.com/docs/authentication/token-types#access-tokens
	// There are not documented lower and upper bounds on the length of the token.
	// But based on the pattern and https://datatracker.ietf.org/doc/html/rfc4648#section-5,
	// token length should be at least 10 characters.
	// The upper bound is based on the assumption that a typical access token is around 256 bits long,
	// which is true for real examples and documentation.
	// This is needed to avoid matching larger blobs of text.
	tokenRe = regexp.MustCompile(`\bya29\.[a-zA-Z0-9_-]{10,500}`)
)

// NewDetector returns a new simpletoken.Detector that matches GCP OAuth2 access tokens.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     tokenRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return Token{Token: string(b)}, true
		},
	}
}
