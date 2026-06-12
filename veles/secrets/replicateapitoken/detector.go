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

// Package replicateapitoken contains a Veles Secret type and a Detector for
// Replicate API tokens (prefix `r8_`).
package replicateapitoken

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of a Replicate API token.
// Replicate API tokens are `r8_` (3 chars) followed by 37 characters from
// the set [A-Za-z0-9_-].
const maxTokenLength = 40

// keyRe is a regular expression that matches a Replicate API token.
// Replicate API tokens have the form: `r8_` followed by 37 characters from
// the set [A-Za-z0-9_-].
var keyRe = regexp.MustCompile(`r8_[A-Za-z0-9_-]{37}`)

// NewDetector returns a new simpletoken.Detector that matches
// Replicate API tokens.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     keyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return ReplicateAPIToken{Key: string(b)}, true
		},
	}
}
