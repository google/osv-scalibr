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

package github

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
	checksum "github.com/google/osv-scalibr/veles/secrets/github/checksum"
)

const oauthTokenBase64MaxLen = 56 // 40 bytes, base64 encoded

// base64(gho_) -> Z2hvX (minus the last incomplete byte)
var oauthTokenPattern = regexp.MustCompile(`gho_[A-Za-z0-9]{36}`)
var oauthTokenBase64Pattern = regexp.MustCompile(`Z2hvX[0-9a-zA-Z+/=]{0,51}`)

// NewOAuthTokenDetector returns a new Veles Detector that finds Github oauth tokens.
func NewOAuthTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen:   oauthTokenBase64MaxLen,
		Re:       oauthTokenPattern,
		ReBase64: oauthTokenBase64Pattern,
		FromMatch: func(match []byte) (veles.Secret, bool) {
			if !checksum.Validate(match) {
				return nil, false
			}
			return OAuthToken{Token: string(match)}, true
		},
	}
}
