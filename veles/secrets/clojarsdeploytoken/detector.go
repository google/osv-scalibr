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

// maxTokenLength is the fixed size of a Clojars Deploy Token.
// "CLOJARS_" (8 chars) + 60 hex chars = 68 chars.
const maxTokenLength = 68

// keyRe matches the strict format: "CLOJARS_" followed by exactly 60 hex characters.
// A-F in the regex is not required. But to avoid false negatives, I added it.
// Having it there does not cause any harm since due to prefix of CLOAJARS_ that will not
// introduce false positives
var keyRe = regexp.MustCompile(`CLOJARS_[a-fA-F0-9]{60}`)

// NewDetector returns a new simpletoken.Detector that matches
// Clojars Deploy Tokens.
func NewDetector() veles.Detector {
	return &simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     keyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return ClojarsDeployToken{Token: string(b)}, true
		},
	}
}
