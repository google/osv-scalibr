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

package appservertoservertoken

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletokenwithok"
	"github.com/google/osv-scalibr/veles/secrets/github/token"
)

const tokenMaxLen = 40

var tokenPattern = regexp.MustCompile(`ghs_[A-Za-z0-9]{36}`)

// NewDetector returns a new Veles Detector that finds Github app server to server tokens
func NewDetector() veles.Detector {
	return simpletokenwithok.Detector{
		MaxLen: tokenMaxLen,
		Re:     tokenPattern,
		FromMatch: func(match []byte) (veles.Secret, bool) {
			if !token.ValidateChecksum(match) {
				return nil, false
			}
			return GithubAppServerToServerToken{Token: string(match)}, true
		},
	}
}
