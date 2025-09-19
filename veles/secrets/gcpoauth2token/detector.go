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
// Pattern: 1/ followed by alphanumeric characters, underscores, and hyphens
var tokenRe = regexp.MustCompile(`1/[A-Za-z0-9_-]{10,}`)

// NewDetector returns a new simpletoken.Detector that matches GCP OAuth2 access tokens.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     tokenRe,
		FromMatch: func(b []byte) veles.Secret {
			return GCPOAuth2AccessToken{Token: string(b)}
		},
	}
}
