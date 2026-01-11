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

package sendgrid

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure the constructor satisfies the interface at compile time.
	_ veles.Detector = NewDetector()
)

// SendGrid API keys are exactly 69 characters: SG.<22 chars>.<43 chars>
const maxKeyLen = 69

var keyRe = regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`)

// NewDetector returns a detector for SendGrid API keys (SG.xxx.yyy).
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxKeyLen,
		Re:     keyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return APIKey{Key: string(b)}, true
		},
	}
}
