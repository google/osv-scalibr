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

// Package clojarsdeploytoken contains a Veles Secret type and a Detector for
// Clojars Deploy Tokens (prefix `CLOJARS_`).
package clojarsdeploytoken

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of a Clojars deploy token.
const maxTokenLength = 68

// tokenRe is a regular expression that matches a Clojars deploy token.
// Clojars deploy tokens have the form: `CLOJARS_` followed by exactly 60
// lowercase hexadecimal characters.
var tokenRe = regexp.MustCompile(`CLOJARS_[a-f0-9]{60}`)

// NewDetector returns a new simpletoken.Detector that matches
// Clojars deploy tokens.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     tokenRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return ClojarsDeployToken{Token: string(b)}, true
		},
	}
}
