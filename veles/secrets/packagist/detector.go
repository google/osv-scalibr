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

package packagist

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Detector = NewAPIKeyDetector()
	_ veles.Detector = NewAPISecretDetector()
)

const (
	apiKeyMaxLen    = 50  // packagist_ack_ (14) + ~32 hex chars + padding
	apiSecretMaxLen = 100 // packagist_acs_ (14) + ~80 hex chars + padding
	// maxDistance is the maximum distance between API key and secret to be considered for pairing.
	// 10 KiB is a good upper bound as credentials are typically close together in config files.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

// apiKeyRe matches Packagist API Keys in the format:
// packagist_ack_[0-9a-f]{28,32}
// Based on observed format: 28-32 hex characters after prefix
var apiKeyRe = regexp.MustCompile(`packagist_ack_[0-9a-f]{28,32}`)

// apiSecretRe matches Packagist API Secrets in the format:
// packagist_acs_[0-9a-f]{64,96}
// Based on observed format: typically 80 hex characters after prefix
var apiSecretRe = regexp.MustCompile(`packagist_acs_[0-9a-f]{64,96}`)

// NewAPIKeyDetector returns a detector for Packagist API Keys.
func NewAPIKeyDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: apiKeyMaxLen,
		Re:     apiKeyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return APIKey{Key: string(b)}, true
		},
	}
}

// NewAPISecretDetector returns a detector for Packagist API Secrets.
// This detector finds secrets along with their corresponding API Keys when both are found together.
// The Key field will be populated, enabling HMAC validation.
// Note: This detector requires BOTH key and secret to be present (within 10KB distance).
func NewAPISecretDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(apiKeyMaxLen, apiSecretMaxLen),
		MaxDistance:   maxDistance,
		FindA:         pair.FindAllMatches(apiKeyRe),
		FindB:         pair.FindAllMatches(apiSecretRe),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return APISecret{
				Secret: string(p.B.Value),
				Key:    string(p.A.Value),
			}, true
		},
	}
}
