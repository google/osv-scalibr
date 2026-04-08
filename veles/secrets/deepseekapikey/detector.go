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

package deepseekapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of a DeepSeek API key.
const maxTokenLength = 100

// keyRe is a regular expression that matches a DeepSeek API key.
// DeepSeek API keys start with "sk-" followed by exactly 32 lowercase
// alphanumeric characters (a-z, 0-9). The pattern uses word boundaries (\b)
// to avoid matching substrings within larger tokens.
// Example: sk-15ac903f2e481u3d4f9g2u3ia8e2b73n
var keyRe = regexp.MustCompile(`\bsk-[a-z0-9]{32}\b`)

// NewDetector returns a new simpletoken.Detector that matches DeepSeek API keys.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     keyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return APIKey{Key: string(b)}, true
		},
	}
}
