// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package recaptcha

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Detector = NewDetector()
)

const recaptchaMaxLen = 40

// recaptchaRe matches reCAPTCHA secret keys, which typically start with '6' followed by 39 characters.
// The allowed characters are alphanumeric, underscore, and hyphen.
// Example matched key: "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"
var recaptchaRe = regexp.MustCompile(`6[0-9a-zA-Z_-]{39}`)

// NewDetector returns a detector for reCAPTCHA secret keys.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: recaptchaMaxLen,
		Re:     recaptchaRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return CaptchaSecret{Key: string(b)}, true
		},
	}
}
