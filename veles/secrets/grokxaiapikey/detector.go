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

// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package grokxaiapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Detector = NewAPIKeyDetector()
	_ veles.Detector = NewManagementKeyDetector()
)

// API key: prefix `xai-` followed by 80 alphanumeric characters.
const apiKeyMaxLen = 84

var apiKeyRe = regexp.MustCompile(`xai-[A-Za-z0-9]{80}`)

// Management key: prefix `xai-token-` followed by 80 alphanumeric characters.
const mgmtKeyMaxLen = 90

var mgmtKeyRe = regexp.MustCompile(`xai-token-[A-Za-z0-9]{80}`)

// NewAPIKeyDetector returns a detector for standard xAI API keys (xai-...).
func NewAPIKeyDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: apiKeyMaxLen,
		Re:     apiKeyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return GrokXAIAPIKey{Key: string(b)}, true
		},
	}
}

// NewManagementKeyDetector returns a detector for xAI management keys (xai-token-...).
func NewManagementKeyDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: mgmtKeyMaxLen,
		Re:     mgmtKeyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return GrokXAIManagementKey{Key: string(b)}, true
		},
	}
}
