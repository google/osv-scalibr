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

const s2sTokenMaxLen = 40

var s2sTokenPattern = regexp.MustCompile(`ghs_[A-Za-z0-9]{36}`)

// NewAppS2STokenDetector returns a new Veles Detector that finds Github app server to server tokens
func NewAppS2STokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: s2sTokenMaxLen,
		Re:     s2sTokenPattern,
		FromMatch: func(match []byte) (veles.Secret, bool) {
			if !checksum.Validate(match) {
				return nil, false
			}
			return AppServerToServerToken{Token: string(match)}, true
		},
	}
}
