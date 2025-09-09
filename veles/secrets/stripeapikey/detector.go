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

package stripeapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Detector = NewSKTestDetector()
	_ veles.Detector = NewSKLiveDetector()
	_ veles.Detector = NewRKTestDetector()
	_ veles.Detector = NewRKLiveDetector()
	_ veles.Detector = NewWebhookSecretDetector()
)

// Approximate max lengths for stripe keys.
const (
	// Secret keys max length (prefix 8 + 99 payload)
	skKeyMaxLen   = 107
	// Restricted keys max length (prefix 8 + 99 payload)
	rkKeyMaxLen   = 107
	// Webhook secret max length (prefix 6 + 32 payload)
	webhookMaxLen = 38
)

// Regexes for Stripe keys and webhook secret. Initialized at startup.
var (
	// Stripe Secret Key (Test): starts with "sk_test_" followed by 10-99 alphanumeric characters
	skTestRe = regexp.MustCompile(`sk_test_[A-Za-z0-9]{10,99}\b`)

	// Stripe Secret Key (Live): starts with "sk_live_" followed by 10-99 alphanumeric characters
	skLiveRe = regexp.MustCompile(`sk_live_[A-Za-z0-9]{10,99}\b`)

	// Stripe Restricted Key (Test): starts with "rk_test_" followed by 10-99 alphanumeric characters
	rkTestRe = regexp.MustCompile(`rk_test_[A-Za-z0-9]{10,99}\b`)

	// Stripe Restricted Key (Live): starts with "rk_live_" followed by 10-99 alphanumeric characters
	rkLiveRe = regexp.MustCompile(`rk_live_[A-Za-z0-9]{10,99}\b`)

	// Stripe Webhook Secret: starts with "whsec_" followed by exactly 32 alphanumeric characters
	webhookRe = regexp.MustCompile(`whsec_[A-Za-z0-9]{32}`)
)


// NewSKTestDetector returns a detector for Stripe test secret keys (sk_test_...).
func NewSKTestDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: skKeyMaxLen,
		Re:     skTestRe,
		FromMatch: func(b []byte) veles.Secret {
			return StripeSKTestKey{Key: string(b)}
		},
	}
}

// NewSKLiveDetector returns a detector for Stripe live secret keys (sk_live_...).
func NewSKLiveDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: skKeyMaxLen,
		Re:     skLiveRe,
		FromMatch: func(b []byte) veles.Secret {
			return StripeSKLiveKey{Key: string(b)}
		},
	}
}

// NewRKTestDetector returns a detector for Stripe restricted test keys (rk_test_...).
func NewRKTestDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: rkKeyMaxLen,
		Re:     rkTestRe,
		FromMatch: func(b []byte) veles.Secret {
			return StripeRKTestKey{Key: string(b)}
		},
	}
}

// NewRKLiveDetector returns a detector for Stripe restricted live keys (rk_live_...).
func NewRKLiveDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: rkKeyMaxLen,
		Re:     rkLiveRe,
		FromMatch: func(b []byte) veles.Secret {
			return StripeRKLiveKey{Key: string(b)}
		},
	}
}

// NewWebhookSecretDetector returns a detector for Stripe webhook secrets (whsec_...).
func NewWebhookSecretDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: webhookMaxLen,
		Re:     webhookRe,
		FromMatch: func(b []byte) veles.Secret {
			return StripeWebhookSecret{Key: string(b)}
		},
	}
}
