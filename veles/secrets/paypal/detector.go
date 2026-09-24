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
	// Secret for them to be considered a pair. A Client ID and Secret almost always
	// leak adjacently, so a tight bound avoids pairing unrelated matches.
	maxDistance = 200
)

var (
	// clientIDRe matches PayPal REST API Client IDs.
	//
	// PayPal does not publish a formal grammar. Based on credentials issued by
	// the Developer Dashboard across both Sandbox and Live environments, Client
	// IDs are URL-safe strings ([A-Za-z0-9_-]) that commonly begin with "A" and
	// are ~80 characters long. To limit false positives, the value must begin with
	// "A" at a word boundary and be preceded by a PayPal/client-id context keyword.
	// The credential is capture group 1.
	clientIDRe = regexp.MustCompile(`(?i:paypal(?:[ _-]?client)?[ _-]?id|client[ _-]?id|paypal)["':=\s]{1,25}\b(A[A-Za-z0-9_-]{49,99})`)

	// clientSecretRe matches PayPal REST API Client Secrets.
	//
	// Client Secrets follow the same URL-safe shape as Client IDs but commonly
	// begin with "E". As with the Client ID, a PayPal/client-secret context keyword
	// and a word-boundary "E" prefix limit false positives. The credential is
	// capture group 1.
	clientSecretRe = regexp.MustCompile(`(?i:paypal(?:[ _-]?client)?[ _-]?secret(?:[ _-]?key)?|client[ _-]?secret|paypal)["':=\s]{1,25}\b(E[A-Za-z0-9_-]{49,99})`)
)

// findPairElement adapts a context-anchored regex (capture group 1 is the
// credential) for pair.Detector. It reports the position at the start of the
// matched payload and the credential as the value, so the position points at the
// payload while the reported secret value stays clean.
func findPairElement(re *regexp.Regexp) func(data []byte) []*pair.Match {
	return func(data []byte) []*pair.Match {
		var out []*pair.Match
		for _, m := range re.FindAllSubmatchIndex(data, -1) {
			// m[0:2] full match (keyword+credential); m[2:4] capture group 1 (credential).
			if len(m) < 4 || m[2] < 0 {
				continue
			}
			out = append(out, &pair.Match{Start: m[0], Value: data[m[2]:m[3]]})
		}
		return out
	}
}

// NewDetector returns a new Veles Detector that finds PayPal REST API
// credentials. It reports a Credentials secret only when a Client ID and a
// Client Secret are found within maxDistance of each other, because the
// Validator requires both values to authenticate.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(maxClientIDLen, maxClientSecretLen),
		MaxDistance:   maxDistance,
		FindA:         findPairElement(clientIDRe),
		FindB:         findPairElement(clientSecretRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return Credentials{ID: string(p.A.Value), Secret: string(p.B.Value)}, true
		},
	}
}
