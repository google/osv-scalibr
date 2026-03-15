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

// Package qwenpat contains a Veles Secret type and a Detector for
// Qwen AI API Service Accounts key (prefix `sk-`).
package qwenpat

import (
        "regexp"

        "github.com/google/osv-scalibr/veles"
        "github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)
// maxTokenLength is the maximum size of a Qwen PAT.
const maxTokenLength = 35

// patRe is a regular expression that matches a Qwen AI API Service Accounts key.
// Qwen AI API Service Accounts key have the form: `sk-` followed by 32
// alphanumeric characters.
// See following links:
// 1. https://www.alibabacloud.com/help/en/model-studio/get-api-key
// 2. https://qwenlm.github.io/qwen-code-docs/en/users/configuration/auth/#-option-2-api-key-flexible
var patRe = regexp.MustCompile(`sk-[A-Za-z0-9]{32}`)


// NewDetector returns a new simpletoken.Detector that matches OpenAI API keys
// (both legacy and project-scoped formats).
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     patRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return APIKey{Key: string(b)}, true
		},
	}
}
