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

// Package groqapikey contains a Veles Secret type and a Detector for
// Groq API keys (prefix `gsk_`).
package groqapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of a Groq API key.
// Groq API keys are `gsk_` (4 chars) followed by 52 alphanumeric characters.
const maxTokenLength = 56

// keyRe is a regular expression that matches a Groq API key.
// Groq API keys have the form: `gsk_` followed by 52 alphanumeric characters.
var keyRe = regexp.MustCompile(`gsk_[A-Za-z0-9]{52}`)

// NewDetector returns a new simpletoken.Detector that matches
// Groq API keys.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     keyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return GroqAPIKey{Key: string(b)}, true
		},
	}
}
