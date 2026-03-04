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

package paypal

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Detector = NewClientIDDetector()
	_ veles.Detector = NewClientSecretDetector()
)

// PayPal Client ID regex.
//
// PayPal Client IDs start with "A" followed by alphanumeric characters and
// hyphens. They are typically 80 characters long but can vary between 50-100.
//
// Examples:
//   - AYSq3RDGsmBLJE-otTkBtM-jBRd1TCQwFf9RGfwddNXWz0uFU9ztymylOhRS
//   - AbCdEfGhIjKlMnOpQrStUvWxYz0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567890123456789
const clientIDMaxLen = 100

var clientIDRe = regexp.MustCompile(`A[A-Za-z0-9_-]{49,99}`)

// PayPal Client Secret regex.
//
// PayPal Client Secrets are alphanumeric strings (potentially including
// hyphens and underscores) that are typically 80 characters long.
// They start with "E" and are similar in format to the Client ID.
//
// To reduce false positives, we look for the "E" prefix which is common
// in PayPal secrets.
const clientSecretMaxLen = 100

var clientSecretRe = regexp.MustCompile(`E[A-Za-z0-9_-]{49,99}`)

// NewClientIDDetector returns a detector for PayPal Client IDs.
func NewClientIDDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: clientIDMaxLen,
		Re:     clientIDRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return ClientID{Key: string(b)}, true
		},
	}
}

// NewClientSecretDetector returns a detector for PayPal Client Secrets.
func NewClientSecretDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: clientSecretMaxLen,
		Re:     clientSecretRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return ClientSecret{Key: string(b)}, true
		},
	}
}
