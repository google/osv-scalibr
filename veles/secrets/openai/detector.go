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

package openai

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of an OpenAI Project API key.
const maxTokenLength = 200

// keyRe is a regular expression that matches OpenAI API keys.
// Supports legacy format: sk-[chars]T3BlbkFJ[chars]
// and project and service account formats:
//
//	sk-proj-[chars]T3BlbkFJ[chars]
//	sk-svcacct-[chars]T3BlbkFJ[chars]
//
// The regex is designed to be specific enough to avoid false positives.
var keyRe = regexp.MustCompile(
	`sk-[A-Za-z0-9_-]*T3BlbkFJ[A-Za-z0-9_-]+`)

// NewDetector returns a new simpletoken.Detector that matches OpenAI API keys
// (both legacy and project-scoped formats).
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     keyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return APIKey{Key: string(b)}, true
		},
	}
}
