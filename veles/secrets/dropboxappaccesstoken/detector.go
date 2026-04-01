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

// maxTokenLength is the maximum size of a Dropbox short-lived access token.
// These tokens are base64-encoded and typically 130-200+ characters.
const maxTokenLength = 500

// tokenRe matches Dropbox short-lived access tokens.
// These tokens have a distinctive "sl." prefix followed by base64url-safe
// characters (alphanumeric, hyphen, underscore). The minimum length after the
// prefix is set to 100 to avoid false positives.
//
// Reference: https://www.dropbox.com/developers/documentation/http/documentation
var tokenRe = regexp.MustCompile(`sl\.[A-Za-z0-9_-]{100,}`)

// NewDetector returns a new simpletoken.Detector that matches Dropbox
// short-lived access tokens with the "sl." prefix.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     tokenRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return AccessToken{Token: string(b)}, true
		},
	}
}
