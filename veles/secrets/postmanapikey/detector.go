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

package postmanapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Detector = NewAPIKeyDetector()
	_ veles.Detector = NewCollectionTokenDetector()
)

// PMAK (Postman API Key) structure seen in examples:
//
//	PMAK-68b96b83f4b88500014cc8d1-d5cba29fdcc8434ed67e4ed2fe95a521e5
//
// Pattern: "PMAK-" + 24 hex chars + "-" + 34 hex chars.
const pmakMaxLen = 64

var pmakRe = regexp.MustCompile(`PMAK-[A-Fa-f0-9]{24}-[A-Fa-f0-9]{34}`)

// PMAT (Postman Collection Access Token) structure seen in examples:
//
//	PMAT-01K4A58P2HS2Q43TXHSXFRDBZX
//
// Pattern: "PMAT-" + 26 alphanumeric characters.
const pmatMaxLen = 31

var pmatRe = regexp.MustCompile(`PMAT-[A-Za-z0-9]{26}`)

// NewAPIKeyDetector returns a detector for Postman API keys (PMAK-...).
func NewAPIKeyDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: pmakMaxLen,
		Re:     pmakRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return PostmanAPIKey{Key: string(b)}, true
		},
	}
}

// NewCollectionTokenDetector returns a detector for Postman collection
// access tokens (PMAT-...).
func NewCollectionTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: pmatMaxLen,
		Re:     pmatRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return PostmanCollectionToken{Key: string(b)}, true
		},
	}
}
