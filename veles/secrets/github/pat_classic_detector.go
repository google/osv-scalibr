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

package github

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
	checksum "github.com/google/osv-scalibr/veles/secrets/github/checksum"
)

const classicPATBase64MaxLen = 56 // 40 bytes, base64 encoded

var classicPATPattern = regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)

// base64(ghp_) -> Z2hwX (minus the last incomplete byte)
var classicPATBase64Pattern = regexp.MustCompile(`Z2hwX[0-9a-zA-Z+/=]{0,51}`)

// NewClassicPATDetector returns a new Veles Detector that finds Github classic personal access tokens
func NewClassicPATDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen:   classicPATBase64MaxLen,
		Re:       classicPATPattern,
		ReBase64: classicPATBase64Pattern,
		FromMatch: func(match []byte) (veles.Secret, bool) {
			if !checksum.Validate(match) {
				return nil, false
			}
			return ClassicPersonalAccessToken{Token: string(match)}, true
		},
	}
}
