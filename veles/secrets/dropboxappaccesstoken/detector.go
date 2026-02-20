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

package dropboxappaccesstoken

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of a Dropbox App access token.
// Dropbox short-lived access tokens can be very long (1000+ characters).
const maxTokenLength = 1500

// keyRe is a regular expression that matches Dropbox App access tokens.
// All Dropbox short-lived access tokens start with "sl.u." followed by
// a long string of alphanumeric characters, hyphens, and underscores.
var keyRe = regexp.MustCompile(
	`sl\.u\.[A-Za-z0-9_-]{50,}`)

// NewDetector returns a new simpletoken.Detector that matches Dropbox App
// access tokens.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     keyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return APIAccessToken{Token: string(b)}, true
		},
	}
}
