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

package googleaistudiokey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// aiStudioKeyRe matches Google AI Studio (Gemini) API keys.
	// Format: AIzaSy... (39 characters total)
	aiStudioKeyRe = regexp.MustCompile(`(?i)\bAIzaSy[a-zA-Z0-9-_]{33}\b`)
)

// NewDetector returns a detector for Google AI Studio keys.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: 1024,
		Re:     aiStudioKeyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return GoogleAIStudioKey{Key: string(b)}, true
		},
	}
}
