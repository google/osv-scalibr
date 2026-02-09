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

package paystacksecretkey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Detector = NewSecretKeyDetector()
)

// skMaxLen defines the maximum allowed size of a PayStack token.
//
// There is no official explanation for the PayStack token upper limit length.
// However, in practice Secret Keys are typically transmitted as Bearer token in HTTP headers,
// where very large values can cause interoperability issues. Exceeding 8 KB is
// generally discouraged, as many servers, proxies, and libraries impose limits
// around this size.
const skMaxLen = 58

// Secret Keys can be found with this regex, ex: sk_test_abcd1234efgh5678ijkl9012mnop3456qrstuvff
var skRe = regexp.MustCompile(`\bsk_[a-z]{1,15}_[a-z0-9]{40}\b`)

// NewSecretKeyDetector returns a detector for PayStack Secret Keys (sk_...).
func NewSecretKeyDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: skMaxLen,
		Re:     skRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return PaystackSecret{Key: string(b)}, true
		},
	}
}
