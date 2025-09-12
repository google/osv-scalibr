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

package githubapprefreshtoken

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

const tokenMaxLen = 80

var tokenPattern = regexp.MustCompile(`ghr_[A-Za-z0-9]{76}`)

// NewDetector returns a new Veles Detector that finds Github app refresh tokens
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: tokenMaxLen,
		Re:     tokenPattern,
		FromMatch: func(b []byte) veles.Secret {
			return GithubAppRefreshToken{Token: string(b)}
		},
	}
}
