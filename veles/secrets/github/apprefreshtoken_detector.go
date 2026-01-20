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

const appRefreshTokenBase64MaxLen = 109 // 80 bytes, base64 encoded

var appRefreshTokenPattern = regexp.MustCompile(`ghr_[A-Za-z0-9]{76}`)

// base64(ghr_) -> Z2hyX (minus the last incomplete byte)
var appRefreshTokenBase64Pattern = regexp.MustCompile(`Z2hyX[0-9a-zA-Z+/=]{0,104}`)

// NewAppRefreshTokenDetector returns a new Veles Detector that finds Github app refresh tokens
func NewAppRefreshTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen:   appRefreshTokenBase64MaxLen,
		Re:       appRefreshTokenPattern,
		ReBase64: appRefreshTokenBase64Pattern,
		FromMatch: func(match []byte) (veles.Secret, bool) {
			if !checksum.Validate(match) {
				return nil, false
			}
			return AppRefreshToken{Token: string(match)}, true
		},
	}
}
