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

package openrouter

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of an OpenRouter API key.
const maxTokenLength = 100

// keyRe is a regular expression that matches OpenRouter API keys.
// OpenRouter API keys typically start with "sk-or-v" followed by a version number,
// then alphanumeric characters, underscores, and hyphens. The regex is designed to be specific enough to avoid false positives.
var keyRe = regexp.MustCompile(`sk-or-v[0-9]+-[A-Za-z0-9_-]{20,}`)

// NewDetector returns a new simpletoken.Detector that matches OpenRouter API keys.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     keyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return APIKey{Key: string(b)}, true
		},
	}
}
