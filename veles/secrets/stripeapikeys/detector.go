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
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stripeapikeys

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Detector = NewSecretKeyDetector()
	_ veles.Detector = NewRestrictedKeyDetector()
	_ veles.Detector = NewWebhookSecretDetector()
)

// Secret Keys Live (SK) regex: sk_live_[A-Za-z0-9]{10,99}
const skMaxLen = 107 // Max length of the key itself, plus "sk_live_"
var skRe = regexp.MustCompile(`sk_live_[A-Za-z0-9]{10,99}`)

// Secret Keys Restricted (RK) regex: rk_live_[A-Za-z0-9]{10,99}
const rkMaxLen = 107 // Max length of the key itself, plus "rk_live_"
var rkRe = regexp.MustCompile(`rk_live_[A-Za-z0-9]{10,99}`)

// Stripe Webhook Signing Secrets regex: whsec_[A-Za-z0-9]{32}
const whsecMaxLen = 38 // Max length of the key itself, plus "whsec_"
var whsecRe = regexp.MustCompile(`whsec_[A-Za-z0-9]{32}`)

// NewSecretKeyDetector returns a detector for Stripe Secret Keys (sk_live_...).
func NewSecretKeyDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: skMaxLen,
		Re:     skRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return StripeSecretKey{Key: string(b)}, true
		},
	}
}

// NewRestrictedKeyDetector returns a detector for Stripe Restricted Keys (rk_live_...).
func NewRestrictedKeyDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: rkMaxLen,
		Re:     rkRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return StripeRestrictedKey{Key: string(b)}, true
		},
	}
}

// NewWebhookSecretDetector returns a detector for Stripe Webhook Signing Secrets (whsec_...).
func NewWebhookSecretDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: whsecMaxLen,
		Re:     whsecRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return StripeWebhookSecret{Key: string(b)}, true
		},
	}
}
