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

package qwenaiapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of a Qwen AI API key.
// Format: "sk-" + 32 hex chars = 35 chars.
const maxTokenLength = 50

// keyRe matches Qwen AI API keys.
// Qwen keys start with "sk-" followed by exactly 32 lowercase alphanumeric
// characters. This is distinct from OpenAI keys which require the "T3BlbkFJ"
// marker and use mixed case, and from other "sk-" prefixed keys which differ
// in length and character set.
var keyRe = regexp.MustCompile(`\bsk-[a-z0-9]{32}\b`)

// NewDetector returns a new simpletoken.Detector that matches Qwen AI API keys.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     keyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return APIKey{Key: string(b)}, true
		},
	}
}
