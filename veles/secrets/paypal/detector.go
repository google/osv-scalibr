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
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

const (
	// maxClientIDLen is an upper bound on the length of a PayPal Client ID.
	// PayPal does not publish a formal length; observed values are ~80 chars.
	maxClientIDLen = 100
	// maxClientSecretLen is an upper bound on the length of a PayPal Client
	// Secret. PayPal does not publish a formal length; observed values are
	// ~80 chars.
	maxClientSecretLen = 100
	// maxDistance is the maximum distance between a Client ID and a Client
	// Secret for them to be considered a pair. 10 KiB is a good upper bound as
	// we don't expect files containing credentials to be larger than this.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

var (
	// clientIDRe matches PayPal REST API Client IDs.
	//
	// PayPal does not publish a formal grammar. Based on credentials issued by
	// the Developer Dashboard across both Sandbox and Live environments, Client
	// IDs are URL-safe strings ([A-Za-z0-9_-]) that commonly begin with "A" and
	// are ~80 characters long. The leading "A" anchor and length floor keep the
	// pattern conservative to limit false positives.
	clientIDRe = regexp.MustCompile(`A[A-Za-z0-9_-]{49,99}`)

	// clientSecretRe matches PayPal REST API Client Secrets.
	//
	// Client Secrets follow the same URL-safe shape as Client IDs but commonly
	// begin with "E". The leading "E" anchor disambiguates them from Client IDs
	// and limits false positives.
	clientSecretRe = regexp.MustCompile(`E[A-Za-z0-9_-]{49,99}`)
)

// NewDetector returns a new Veles Detector that finds PayPal REST API
// credentials. It reports a Credentials secret only when a Client ID and a
// Client Secret are found within maxDistance of each other, because the
// Validator requires both values to authenticate.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(maxClientIDLen, maxClientSecretLen),
		MaxDistance:   maxDistance,
		FindA:         pair.FindAllMatches(clientIDRe),
		FindB:         pair.FindAllMatches(clientSecretRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return Credentials{ID: string(p.A.Value), Secret: string(p.B.Value)}, true
		},
	}
}
