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

// Package huggingfaceapikey contains a Veles Secret type and a Detector for
// Huggingface API keys (prefix `hf_`).
package huggingfaceapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of a Huggingface API key.
const maxTokenLength = 37

// keyRe is a regular expression that matches a Huggingface API key.
// Huggingface API keys have the form: `hf_` followed by 34
// alphabet characters.
var keyRe = regexp.MustCompile(`hf_[A-Za-z]{34}`)

// NewDetector returns a new simpletoken.Detector that matches
// Huggingface API keys.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     keyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return HuggingfaceAPIKey{Key: string(b)}, true
		},
	}
}
